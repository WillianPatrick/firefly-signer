// Copyright © 2024 Willian Patrick dos Santos - superhitec@gmail.com
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awswallet

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/karlseguin/ccache"
)

// algorithmIdentifier represents the algorithm identifier in ASN.1 encoding.
type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// subjectPublicKeyInfo represents the SubjectPublicKeyInfo structure in ASN.1 encoding.
type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// Wallet interface defines the necessary methods for the KMS wallet.
type Wallet interface {
	ethsigner.WalletTypedData
	CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error)
	AddMappingKeyAddress(address string, data []byte) error
	Initialize(ctx context.Context) error
	Close() error
}

// kmsWallet implements the Wallet interface using AWS KMS.
type kmsWallet struct {
	conf            Config
	secretsClient   *secretsmanager.Client
	secretsCache    *ccache.Cache
	secretsCacheTTL time.Duration

	mux sync.Mutex

	kmsClient                           *kms.Client
	kmsMappingAddressKeyNameStopRefresh chan struct{}
	kmsMappingAddressKeyName            map[string][]byte
}

// AWSKMSTimeout defines the timeout duration for AWS KMS operations.
const AWSKMSTimeout = 30 * time.Second

// NewAWSKMSWallet initializes a new kmsWallet instance.
func NewAWSKMSWallet(ctx context.Context, conf *Config) (Wallet, error) {
	w := &kmsWallet{
		conf: *conf,
	}

	var awsCfg aws.Config
	var err error

	if conf.AccessKeyID != "" && conf.SecretAccessKey != "" {
		log.L(ctx).Debugf("AWS: Using static credentials.")
		creds := awscreds.NewStaticCredentialsProvider(conf.AccessKeyID, conf.SecretAccessKey, "")
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(conf.Region),
			config.WithCredentialsProvider(creds),
		)
	} else {
		log.L(ctx).Debugf("AWS: Using default credentials provider.")
		awsCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(conf.Region))
	}

	if err != nil {
		return nil, fmt.Errorf("AWS: failed to load AWS configuration: %w", err)
	}

	stsClient := sts.NewFromConfig(awsCfg)
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("AWS: failed to get caller identity: %w", err)
	}
	log.L(ctx).Debugf("AWS: Successfully authenticated as %s", *callerIdentity.Arn)

	if w.conf.KMS.Enabled {
		log.L(ctx).Debugf("AWS KMS: Enabled")
		w.kmsClient = kms.NewFromConfig(awsCfg)
	}

	if w.conf.Secrets.Enabled {
		log.L(ctx).Debugf("AWS Secrets: Enabled")
		w.secretsClient = secretsmanager.NewFromConfig(awsCfg)
		if w.conf.Secrets.Cache.Enabled {
			log.L(ctx).Debugf("AWS Secrets - Cache: Enabled")
			maxSize := w.conf.Secrets.Cache.MaxSize
			if maxSize == 0 {
				maxSize = int64(100)
			}
			itemsToPrune := w.conf.Secrets.Cache.ItemsToPrune
			if itemsToPrune == 0 {
				itemsToPrune = uint32(10)
			}

			w.secretsCache = ccache.New(ccache.Configure().MaxSize(maxSize).ItemsToPrune(itemsToPrune))
			w.secretsCacheTTL = w.conf.Secrets.Cache.TTL
			if w.secretsCacheTTL == 0 {
				w.secretsCacheTTL = 1 * time.Hour
			}
		}
	}

	if !w.conf.Secrets.Enabled && w.conf.KMS.Enabled {
		log.L(ctx).Debugf("AWS KMS - Address Mapping: Enabled")
		w.kmsMappingAddressKeyName = make(map[string][]byte)
	}

	if w.conf.Secrets.Enabled && w.conf.KMS.Enabled {
		log.L(ctx).Debugf("AWS Secrets & KMS Flow - Enabled")
	}

	return w, nil
}

// Initialize starts the refresh loop if mapping is enabled.
func (w *kmsWallet) Initialize(ctx context.Context) error {
	if !w.conf.Secrets.Enabled && w.conf.KMS.Enabled && w.conf.KMS.MappingAddressKeyNameRefresh.Enabled {
		w.startRefreshLoop(ctx)
	}

	if !w.conf.Secrets.Enabled && w.conf.KMS.Enabled {
		err := w.refreshAddressToKeyNameMapping(ctx)
		if err != nil {
			return fmt.Errorf("AWS: failed initialize KMS Key mapping: %w", err)
		}
	}
	return nil
}

// Sign decides whether to perform local or remote signing based on configuration.
func (w *kmsWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if w.conf.KMS.Enabled && !w.conf.Secrets.Enabled {
		return w.RemoteSign(ctx, txn, chainID)
	} else if w.conf.Secrets.Enabled && !w.conf.KMS.Enabled {
		return w.LocalSign(ctx, txn, chainID)
	}
	// Default behavior when both KMS and Secrets are inactive is to use both
	return w.RemoteSignWithSecrets(ctx, txn, chainID)

}

// LocalSign signs the transaction locally using the stored private in secrets.
func (w *kmsWallet) LocalSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxnJSON, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AWS Secrets - Local Sign - Chain ID: %d - From: %s, Unsigned transaction: %s", chainID, key, string(unsignedTxnJSON))

	privateKeyBytes, err := w.getLocalPrivateKey(ctx, from)
	if err != nil {
		return nil, err
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	signedTx, err := txn.Sign(keypair, chainID)
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AWS Secrets - Local Sign - Chain ID: %d - From: %s, Signed transaction", chainID, key)

	return signedTx, nil
}

// getLocalPrivateKey retrieves the local private key from Secrets Manager.
func (w *kmsWallet) getLocalPrivateKey(ctx context.Context, address ethtypes.Address0xHex) ([]byte, error) {
	if !w.conf.Secrets.Enabled {
		return nil, errors.New("AWS Secrets Manager is not enabled")
	}

	addr := common.Address(address).Hex()
	addrHash := w.hashAddress(addr)

	if w.conf.Secrets.Cache.Enabled {
		item := w.secretsCache.Get(addrHash)
		if item != nil && !item.Expired() {
			privateKeyBytes, err := w.decryptData(item.Value().([]byte), addr)
			if err != nil {
				return nil, fmt.Errorf("AWS Secret: failed to retrieve wallet '%s': %w", addr, err)
			}
			return privateKeyBytes, nil
		}
	}

	getSecretInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(addrHash),
	}

	// Use a separate context with timeout for Secrets Manager operation
	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	secretValue, err := w.secretsClient.GetSecretValue(secretsCtx, getSecretInput)
	if err != nil {
		return nil, fmt.Errorf("AWS Secrets: failed to retrieve wallet '%s': %w", addr, err)
	}

	privateKeyBytes, err := w.decryptData(secretValue.SecretBinary, addr)
	if err != nil {
		return nil, fmt.Errorf("AWS Secrets: failed to decode private key hex: %w", err)
	}

	// Verify that the private key is valid
	_, err = crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("AWS Secrets: failed to parse ECDSA private key: %w", err)
	}
	if w.conf.Secrets.Cache.Enabled {
		w.secretsCache.Set(addr, secretValue.SecretBinary, w.secretsCacheTTL)
	}

	return privateKeyBytes, nil
}

// RemoteSign signs the transaction using AWS KMS.
func (w *kmsWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if !w.conf.KMS.Enabled {
		return nil, errors.New("AWS KMS is not enabled")
	}

	// The current flow without using Secrets
	unsignedTxnJSON, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AWS KMS - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction: %s", chainID, key, string(unsignedTxnJSON))

	// Create the transaction object
	signer := types.NewEIP155Signer(big.NewInt(chainID))
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    txn.Nonce.Uint64(),
		To:       (*common.Address)(txn.To),
		Value:    txn.Value.BigInt(),
		Gas:      txn.GasLimit.Uint64(),
		GasPrice: txn.GasPrice.BigInt(),
		Data:     txn.Data,
	})

	// Compute the Keccak-256 hash of the transaction (Ethereum message hash)
	ethHash := signer.Hash(tx)
	sha256Hash := sha256.Sum256(ethHash.Bytes())

	// keyName := w.hashAddress(key)

	keyIDBytes, err := w.decryptData(w.kmsMappingAddressKeyName[w.hashAddress(key)], key)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed: %w", err)
	}

	// Prepare the SignInput for AWS KMS
	signInput := &kms.SignInput{
		KeyId:            aws.String(string(keyIDBytes)),
		Message:          sha256Hash[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	// Call AWS KMS to sign the SHA-256 hash using the separate context
	kmsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()
	signOutput, err := w.kmsClient.Sign(kmsCtx, signInput)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed: %w", err)
	}

	signature := signOutput.Signature
	// Extract r and s components from the signature
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	// Ensure s is in the lower half of the curve order
	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)

	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	// Calculate recovery ID `v`
	v := byte(chainID*2 + 35 + 27)
	if s.Cmp(halfOrder) > 0 {
		v++
	}

	sig := append(append(r.Bytes(), s.Bytes()...), v)

	// Sign the transaction
	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return nil, err
	}

	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AWS KMS - Remote Sign - Chain ID: %d - From: %s, Signed transaction", chainID, key)

	return signedTxBytes, nil
}

// RemoteSignWithSecrets signs the transaction using AWS KMS and Secrets Manager when both are active or both are inactive.
func (w *kmsWallet) RemoteSignWithSecrets(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	// KMS and Secrets are both active or both inactive (default behavior)
	if !w.conf.KMS.Enabled || !w.conf.Secrets.Enabled {
		return nil, errors.New("AWS Secrets and KMS Manager must both be enabled for this operation")
	}

	unsignedTxnJSON, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AWS Secrets & KMS - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction: %s", chainID, key, string(unsignedTxnJSON))

	// Get the KMS KeyId from Secrets Manager
	keyID, err := w.getKMSKeyIDFromSecrets(ctx, from)
	if err != nil {
		return nil, err
	}

	// Create the transaction object
	signer := types.NewEIP155Signer(big.NewInt(chainID))
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    0, // txn.Nonce.Uint64(),
		To:       (*common.Address)(txn.To),
		Value:    txn.Value.BigInt(),
		Gas:      txn.GasLimit.Uint64(),
		GasPrice: txn.GasPrice.BigInt(),
		Data:     txn.Data,
	})

	// Compute the Keccak-256 hash of the transaction (Ethereum message hash)
	ethHash := signer.Hash(tx)
	sha256Hash := sha256.Sum256(ethHash.Bytes())

	// Prepare the SignInput for AWS KMS
	signInput := &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          sha256Hash[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	// Call AWS KMS to sign the SHA-256 hash using the separate context
	kmsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()
	signOutput, err := w.kmsClient.Sign(kmsCtx, signInput)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed: %w", err)
	}

	signature := signOutput.Signature
	// Extract r and s components from the signature
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])

	// Ensure s is in the lower half of the curve order
	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)

	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	// Calculate recovery ID `v`
	v := byte(chainID*2 + 35 + 27)
	if s.Cmp(halfOrder) > 0 {
		v++
	}

	sig := append(append(r.Bytes(), s.Bytes()...), v)

	// Sign the transaction
	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return nil, err
	}

	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AWS Secrets & KMS - Remote Sign - Chain ID: %d - From: %s, Signed transaction", chainID, key)

	return signedTxBytes, nil
}

// getKMSKeyIDFromSecrets retrieves the KMS KeyId associated with an Ethereum address from Secrets Manager.
func (w *kmsWallet) getKMSKeyIDFromSecrets(ctx context.Context, address ethtypes.Address0xHex) (string, error) {
	addr := common.Address(address).Hex()

	addrHash := aws.String(w.hashAddress(addr))
	getSecretInput := &secretsmanager.GetSecretValueInput{
		SecretId: addrHash,
	}

	// Use a separate context with timeout for Secrets Manager operation
	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	secretValue, err := w.secretsClient.GetSecretValue(secretsCtx, getSecretInput)
	if err != nil {
		return "", fmt.Errorf("AWS KMS: failed to retrieve wallet address '%s': %w", addr, err)
	}

	keyBinay, err := w.decryptData(secretValue.SecretBinary, addr)
	if err != nil {
		return "", fmt.Errorf("AWS KMS: failed to decrypt data for wallet address '%s': %w", addr, err)
	}
	keyID := string(keyBinay)

	return keyID, nil
}

// CreateWallet creates a new wallet based on configuration.
func (w *kmsWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if w.conf.KMS.Enabled && w.conf.Secrets.Enabled {
		return w.CreateKeyWithSecrets(ctx, privateKeyHex)
	} else if w.conf.KMS.Enabled && !w.conf.Secrets.Enabled {
		return w.CreateKey(ctx, privateKeyHex)
	}

	if w.conf.Secrets.Enabled && !w.conf.KMS.Enabled {
		addr, err := w.CreateSecret(ctx, password, privateKeyHex)
		return ethsigner.CreateWalletResponse{
			Address: addr.String(),
		}, err
	} else {
		// Default behavior when both KMS and Secrets are inactive is to use both
		return w.CreateKeyWithSecrets(ctx, privateKeyHex)
	}
}

// CreateSecret creates a new secret in AWS Secrets Manager.
func (w *kmsWallet) CreateSecret(ctx context.Context, password string, privateKeyHex string) (ethtypes.Address0xHex, error) {
	var keypair *secp256k1.KeyPair
	var err error
	if privateKeyHex == "" {
		keypair, err = secp256k1.GenerateSecp256k1KeyPair()
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
	} else {
		privateKey, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
		keypair, err = secp256k1.NewSecp256k1KeyPair(privateKey)
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
	}
	err = w.storeKeyPairSecret(ctx, keypair)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}
	return keypair.Address, nil
}

// storeKeyPairSecret stores the key pair in AWS Secrets Manager.
func (w *kmsWallet) storeKeyPairSecret(ctx context.Context, keypair *secp256k1.KeyPair) error {
	if !w.conf.Secrets.Enabled {
		return errors.New("AWS Secrets Manager is not enabled")
	}

	addr := common.Address(keypair.Address).Hex()
	addrHash := aws.String(w.hashAddress(addr))

	// Convert the private key bytes to a hex-encoded string
	privateKeyBytes, err := w.encryptData(keypair.PrivateKeyBytes(), addr, "")
	if err != nil {
		return fmt.Errorf("AWS Secrets: failed to decrypt data for wallet address '%s': %w", addr, err)
	}
	// Attempt to create the secret
	createInput := &secretsmanager.CreateSecretInput{
		Name:         addrHash,
		SecretBinary: privateKeyBytes,
	}

	// Clone the context with a timeout
	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	_, err = w.secretsClient.CreateSecret(secretsCtx, createInput)
	if err == nil {
		// Secret created successfully
		return nil
	}

	// Handle ResourceExistsException using smithy-go
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceExistsException" {
		// Secret already exists, proceed to update it
		putInput := &secretsmanager.PutSecretValueInput{
			SecretId:     addrHash,
			SecretBinary: privateKeyBytes,
		}

		_, putErr := w.secretsClient.PutSecretValue(secretsCtx, putInput)
		if putErr != nil {
			return fmt.Errorf("failed to update existing secret for wallet address '%s': %w", addr, putErr)
		}
		return nil
	}

	// For other errors, return them
	return fmt.Errorf("failed to create secret for wallet address '%s'", addr)
}

// CreateKey creates a new KMS key and associates it with an Ethereum address via tagging.
func (w *kmsWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if !w.conf.KMS.Enabled {
		return ethsigner.CreateWalletResponse{}, errors.New("AWS KMS is not enabled")
	}

	// Clone the context with timeout
	kmsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	input := &kms.CreateKeyInput{
		KeySpec:  kmstypes.KeySpecEccSecgP256k1,
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		Origin:   kmstypes.OriginTypeAwsKms,
	}
	output, err := w.kmsClient.CreateKey(kmsCtx, input)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to create key: %w", err)
	}

	pubKey, err := w.getPublicKeyForKeyName(ctx, *output.KeyMetadata.KeyId)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to get public key: %w", err)
	}

	address := crypto.PubkeyToAddress(*pubKey)

	// Clone the context with timeout for tagging
	tagCtx, cancelTag := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancelTag()

	// Add the tag to the KMS resource for mapping
	addrHash := w.hashAddress(address.Hex())
	_, err = w.kmsClient.TagResource(tagCtx, &kms.TagResourceInput{
		KeyId: output.KeyMetadata.KeyId,
		Tags: []kmstypes.Tag{
			{
				TagKey:   aws.String("EthereumHash"),
				TagValue: aws.String(addrHash),
			},
		},
	})
	if err != nil {
		return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to add tag to key: %w", err)
	}

	if w.conf.KMS.Enabled && !w.conf.Secrets.Enabled {
		w.mux.Lock()
		keyIDBytes, err := w.encryptData([]byte(*output.KeyMetadata.KeyId), address.Hex(), "")
		if err != nil {
			return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to add tag to key: %w", err)
		}
		w.kmsMappingAddressKeyName[addrHash] = keyIDBytes
		w.mux.Unlock()
	}

	log.L(ctx).Debugf("AWS KMS: Created key for ddress %s", address.Hex())

	return ethsigner.CreateWalletResponse{
		Address: address.Hex(),
		KeyName: *output.KeyMetadata.KeyId,
	}, nil
}

// CreateKeyWithSecrets creates a new KMS key and stores the KeyId in Secrets Manager.
func (w *kmsWallet) CreateKeyWithSecrets(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if !w.conf.KMS.Enabled || !w.conf.Secrets.Enabled {
		return ethsigner.CreateWalletResponse{}, errors.New("AWS Secrets and KMS Manager must both be enabled for this operation")
	}

	// Create the KMS key
	resp, err := w.CreateKey(ctx, privateKeyHex)
	if err != nil {
		return resp, err
	}

	// Store the KeyId in Secrets Manager with the Ethereum address as the secret name
	err = w.storeKeyIDInSecrets(ctx, resp.Address, resp.KeyName)
	if err != nil {
		return resp, err
	}

	return resp, nil
}

// storeKeyIDInSecrets stores the KMS KeyId in AWS Secrets Manager.
func (w *kmsWallet) storeKeyIDInSecrets(ctx context.Context, address string, keyID string) error {

	addrHash := aws.String(w.hashAddress(address))

	keyBytes, err := w.encryptData([]byte(keyID), address, "")
	if err != nil {
		return fmt.Errorf("AWS Secrets: failed to decrypt data for wallet address '%s': %w", address, err)
	}

	// Attempt to create the secret
	createInput := &secretsmanager.CreateSecretInput{
		Name:         addrHash,
		SecretBinary: keyBytes,
	}

	// Clone the context with a timeout
	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	_, err = w.secretsClient.CreateSecret(secretsCtx, createInput)
	if err == nil {
		// Secret created successfully
		return nil
	}

	// Handle ResourceExistsException using smithy-go
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceExistsException" {
		// Secret already exists, proceed to update it
		putInput := &secretsmanager.PutSecretValueInput{
			SecretId:     addrHash,
			SecretBinary: keyBytes,
		}

		_, putErr := w.secretsClient.PutSecretValue(secretsCtx, putInput)
		if putErr != nil {
			return fmt.Errorf("failed to update existing secret for wallet address '%s': %w", address, err)
		}
		return nil
	}

	// For other errors, return them
	return fmt.Errorf("failed to create secret for wallet address '%s': %w", address, err)
}

// getPublicKeyForKeyName retrieves the public key associated with a KMS key name.
func (w *kmsWallet) getPublicKeyForKeyName(ctx context.Context, keyName string) (*ecdsa.PublicKey, error) {
	if !w.conf.KMS.Enabled {
		return nil, errors.New("AWS KMS is not enabled")
	}

	// Clone the context with a timeout
	kmsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	input := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyName),
	}
	output, err := w.kmsClient.GetPublicKey(kmsCtx, input)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to get public key for key %s: %w", keyName, err)
	}

	pubKeyDER := output.PublicKey
	log.L(ctx).Debugf("AWS KMS: Received public key of length %d bytes for key %s", len(pubKeyDER), keyName)

	pubKey, err := parsePublicKeyDER(pubKeyDER)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS: %v", err)
	}

	return pubKey, nil
}

// parsePublicKeyDER parses a DER-encoded public key and returns an ECDSA public key.
func parsePublicKeyDER(pubKeyDER []byte) (*ecdsa.PublicKey, error) {
	var spki subjectPublicKeyInfo
	_, err := asn1.Unmarshal(pubKeyDER, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}

	expectedOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	if !spki.Algorithm.Algorithm.Equal(expectedOID) {
		return nil, errors.New("unexpected public key algorithm")
	}

	var curveOID asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse curve OID: %w", err)
	}

	secp256k1OID := asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	if !curveOID.Equal(secp256k1OID) {
		return nil, errors.New("unexpected public key curve")
	}

	pubKeyBytes := spki.SubjectPublicKey.Bytes
	if len(pubKeyBytes) != 65 {
		return nil, errors.New("invalid public key length")
	}
	if pubKeyBytes[0] != 0x04 {
		return nil, errors.New("public key is not uncompressed")
	}

	x := new(big.Int).SetBytes(pubKeyBytes[1:33])
	y := new(big.Int).SetBytes(pubKeyBytes[33:])

	pubKey := &ecdsa.PublicKey{
		Curve: crypto.S256(),
		X:     x,
		Y:     y,
	}

	return pubKey, nil
}

// AddMappingKeyAddress manually adds a mapping between a key and an Ethereum address.
func (w *kmsWallet) AddMappingKeyAddress(address string, data []byte) error {
	if !w.conf.KMS.Enabled || w.conf.Secrets.Enabled {
		return errors.New("mapping feature not enabled")
	}
	w.mux.Lock()
	defer w.mux.Unlock()
	w.kmsMappingAddressKeyName[w.hashAddress(common.HexToAddress(address).Hex())] = data
	return nil
}

// Close stops the refresh loop if it's running.
func (w *kmsWallet) Close() error {
	if w.kmsMappingAddressKeyNameStopRefresh != nil {
		close(w.kmsMappingAddressKeyNameStopRefresh)
	}
	return nil
}

// startRefreshLoop starts a background goroutine to periodically refresh the address-to-keyName mapping.
func (w *kmsWallet) startRefreshLoop(ctx context.Context) {
	if !w.conf.KMS.Enabled || !w.conf.KMS.MappingAddressKeyNameRefresh.Enabled {
		return
	}

	if w.conf.KMS.MappingAddressKeyNameRefresh.Interval <= 0 {
		return
	}

	w.kmsMappingAddressKeyNameStopRefresh = make(chan struct{})

	go func() {
		ticker := time.NewTicker(w.conf.KMS.MappingAddressKeyNameRefresh.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				// Use a separate context with timeout for each refresh operation
				refreshCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
				err := w.refreshAddressToKeyNameMapping(refreshCtx)
				cancel()
				if err != nil {
					log.L(ctx).Errorf("Failed to refresh address-to-keyName mapping: %v", err)
				}
			case <-w.kmsMappingAddressKeyNameStopRefresh:
				return
			}
		}
	}()
}

// SignTypedDataV4 signs EIP-712 typed data using the stored private key.
func (w *kmsWallet) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	privateKeyBytes, err := w.getLocalPrivateKey(ctx, from)
	if err != nil {
		return nil, err
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return ethsigner.SignTypedDataV4(ctx, keypair, payload)
}

// GetAccounts retrieves all Ethereum addresses associated with the KMS keys.
func (w *kmsWallet) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	return nil, nil
}

// Refresh manually triggers the refresh of the address-to-keyName mapping.
func (w *kmsWallet) Refresh(ctx context.Context) error {
	if w.conf.Secrets.Enabled {
		return nil
	}
	// Use a separate context with timeout for refresh
	refreshCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()
	return w.refreshAddressToKeyNameMapping(refreshCtx)
}

// refreshAddressToKeyNameMapping updates the mapping between Ethereum addresses and KMS key names by reading tags.
func (w *kmsWallet) refreshAddressToKeyNameMapping(ctx context.Context) error {
	if !w.conf.KMS.Enabled || w.conf.Secrets.Enabled {
		return errors.New("AWS KMS is not enabled")
	}

	log.L(ctx).Debugf("AWS KMS: Updating address mapping...")

	var nextToken *string

	for {
		input := &kms.ListKeysInput{
			Marker: nextToken,
		}
		output, err := w.kmsClient.ListKeys(ctx, input)
		if err != nil {
			return fmt.Errorf("AWS KMS: failed to list keys: %w", err)
		}

		for _, key := range output.Keys {
			keyID := *key.KeyId

			// Get the tags of the key
			tagsOutput, err := w.kmsClient.ListResourceTags(ctx, &kms.ListResourceTagsInput{
				KeyId: aws.String(keyID),
			})
			if err != nil {
				log.L(ctx).Errorf("AWS KMS: failed to list tags for key %s: %v", keyID, err)
				continue
			}

			var addressHash string
			for _, tag := range tagsOutput.Tags {
				if *tag.TagKey == "EthereumHash" {
					addressHash = *tag.TagValue
					break
				}
			}

			if addressHash == "" {
				// If there is no EthereumAddress tag, skip this key
				continue
			}

			w.mux.Lock()
			dataBytes, err := w.encryptData([]byte(keyID), "", addressHash)
			if err != nil {
				log.L(ctx).Errorf("AWS KMS: failed to list tags for key %s: %v", keyID, err)
				continue
			}

			w.kmsMappingAddressKeyName[addressHash] = dataBytes
			w.mux.Unlock()

			log.L(ctx).Debugf("AWS KMS: Mapped addressHash %s to key %s", addressHash, keyID)
		}

		if output.Truncated {
			nextToken = output.NextMarker
		} else {
			break
		}
	}

	log.L(ctx).Debugf("AWS KMS: Updated %d address mappings", len(w.kmsMappingAddressKeyName))

	return nil
}

func (w *kmsWallet) hashAddress(address string) string {
	addressBytes, _ := hex.DecodeString(strings.ToLower(strings.TrimPrefix(address, "0x") + w.conf.PrivateAddressKey))
	hash := sha256.Sum256(addressBytes)
	return hex.EncodeToString(hash[:])
}

func (w *kmsWallet) encryptData(data []byte, publicAddress string, publicAddressHash string) ([]byte, error) {
	// Normalize the public address (remove '0x' prefix and convert to lowercase)
	// address := strings.ToLower(strings.TrimPrefix(publicAddress, "0x"))

	// Derive a symmetric key using the public address and the global secret key
	// Combine the public address and global secret key
	var keyMaterial string
	if publicAddressHash != "" {
		keyMaterial = publicAddressHash
	} else {
		keyMaterial = w.hashAddress(publicAddress)
	}

	// Compute SHA-256 hash of the combined key material
	hash := sha256.Sum256([]byte(keyMaterial))

	// Use the first 32 bytes of the hash as the AES key
	aesKey := hash[:]

	// Create a new AES cipher using the derived key
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Use GCM mode for encryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce of appropriate size
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Encrypt the data using AES-GCM
	ciphertext := aesGCM.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

// decryptData decrypts the input ciphertext using the public address and a global secret key.
func (w *kmsWallet) decryptData(ciphertext []byte, publicAddress string) ([]byte, error) {
	// Normalize the public address (remove '0x' prefix and convert to lowercase)
	// address := strings.ToLower(strings.TrimPrefix(publicAddress, "0x"))

	// Derive the symmetric key using the same method as in encryption
	keyMaterial := w.hashAddress(publicAddress)
	hash := sha256.Sum256([]byte(keyMaterial))
	aesKey := hash[:]

	// Create a new AES cipher using the derived key
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	// Use GCM mode for decryption
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check that the ciphertext is at least as long as the nonce
	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	// Split the nonce and the actual ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	data, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return data, nil
}
