// Copyright © 2024 Willian Patrick dos Santos
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package awskms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	secretsmanagertypes "github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

type Wallet interface {
	ethsigner.WalletTypedData
	CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error)
	AddMappingKeyAddress(key string, address string) error
	Initialize(ctx context.Context) error
	Close() error
}

type kmsWallet struct {
	conf             Config
	kmsClient        *kms.Client
	secretsClient    *secretsmanager.Client
	stopRefresh      chan struct{}
	addressToKeyName map[common.Address]string
	signerCache      *ccache.Cache
	signerCacheTTL   time.Duration
	mux              sync.Mutex
}

func NewAWSKMSWallet(ctx context.Context, conf *Config) (Wallet, error) {
	w := &kmsWallet{
		conf: *conf,
	}

	var awsCfg aws.Config
	var err error

	if conf.AccessKeyID != "" && conf.SecretAccessKey != "" {
		log.L(ctx).Debugf("AWS KMS: Using static credentials.")
		creds := credentials.NewStaticCredentialsProvider(conf.AccessKeyID, conf.SecretAccessKey, "")
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(conf.Region),
			config.WithCredentialsProvider(creds),
		)
	} else {
		log.L(ctx).Debugf("AWS KMS: Using default credentials provider.")
		awsCfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(conf.Region))
	}

	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to load AWS configuration: %w", err)
	}

	stsClient := sts.NewFromConfig(awsCfg)
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to get caller identity: %w", err)
	}
	log.L(ctx).Debugf("AWS KMS: Successfully authenticated as %s", *callerIdentity.Arn)

	w.kmsClient = kms.NewFromConfig(awsCfg)

	if !w.conf.RemoteSign {
		w.secretsClient = secretsmanager.NewFromConfig(awsCfg)
	}

	w.addressToKeyName = make(map[common.Address]string)

	maxSize := conf.LocalSign.Cache.MaxSize | int64(100)
	itemsToPrune := conf.LocalSign.Cache.ItemsToPrune | uint32(10)

	w.signerCache = ccache.New(ccache.Configure().MaxSize(maxSize).ItemsToPrune(itemsToPrune))

	return w, nil
}

func (w *kmsWallet) Initialize(ctx context.Context) error {
	if w.conf.MappingKeyAddress.Enabled && w.conf.MappingKeyAddress.Refresh.Enabled {
		w.startRefreshLoop(ctx)
	}
	return nil
}

func (w *kmsWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if !w.conf.RemoteSign {
		return w.LocalSign(ctx, txn, chainID)
	}
	return w.RemoteSign(ctx, txn, chainID)
}

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
	log.L(ctx).Debugf("AWSKMS - Local Sign - Chain ID: %d - From: %s, Unsigned transaction txn: %s", chainID, key, string(unsignedTxnJSON))

	var privateKey string
	item := w.signerCache.Get(key)
	if item != nil && !item.Expired() {
		item.Extend(w.signerCacheTTL)
		w.mux.Lock()
		privateKey = item.Value().(string)
		w.mux.Unlock()
	} else {
		privateKey, err := w.getLocalPrivateKey(ctx, from)
		if err != nil {
			return nil, err
		}
		w.signerCache.Set(key, privateKey, w.signerCacheTTL)
	}

	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to retrieve local private key: %w", err)
	}

	privateKeyBytes, err := hex.DecodeString(privateKey)
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

	log.L(ctx).Debugf("AWS KMS - Local Sign - Chain ID: %d - From: %s, Signed transaction: %s", chainID, key, hex.EncodeToString(signedTx))

	return signedTx, nil
}

func (w *kmsWallet) getLocalPrivateKey(ctx context.Context, address ethtypes.Address0xHex) (*ecdsa.PrivateKey, error) {
	addr := common.Address(address).Hex()
	item := w.signerCache.Get(addr)
	if item != nil && !item.Expired() {
		privateKeyHex := item.Value().(string)
		privateKeyBytes, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			return nil, fmt.Errorf("AWS KMS: failed to decode cached private key hex: %w", err)
		}
		privateKey, err := crypto.ToECDSA(privateKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("AWS KMS: failed to parse cached ECDSA private key: %w", err)
		}
		return privateKey, nil
	}

	secretName := addr
	getSecretInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	}

	secretValue, err := w.secretsClient.GetSecretValue(ctx, getSecretInput)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to retrieve secret '%s': %w", secretName, err)
	}

	privateKeyHex := *secretValue.SecretString
	privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to decode private key hex: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to parse ECDSA private key: %w", err)
	}

	w.signerCache.Set(addr, strings.TrimPrefix(privateKeyHex, "0x"), w.conf.LocalSign.Cache.TTL)

	return privateKey, nil
}

func (w *kmsWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxnJSON, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AWSKMS - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction txn: %s", chainID, key, string(unsignedTxnJSON))

	signer := types.NewEIP155Signer(big.NewInt(chainID))
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    txn.Nonce.Uint64(),
		To:       (*common.Address)(txn.To),
		Value:    txn.Value.BigInt(),
		Gas:      txn.GasLimit.Uint64(),
		GasPrice: txn.GasPrice.BigInt(),
		Data:     txn.Data,
	})

	hash := signer.Hash(tx)

	keyName, err := w.getKeyNameForAddress(ctx, from)
	if err != nil {
		return nil, err
	}

	signInput := &kms.SignInput{
		KeyId:            aws.String(keyName),
		Message:          hash[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	signOutput, err := w.kmsClient.Sign(ctx, signInput)
	if err != nil {
		return nil, err
	}

	derSignature := signOutput.Signature

	r, s, err := parseDERSignature(derSignature)
	if err != nil {
		return nil, err
	}

	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)

	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	signature := make([]byte, 64)
	copy(signature, rPadded)
	copy(signature[32:], sPadded)

	publicKey, err := w.getPublicKeyForKeyName(ctx, keyName)
	if err != nil {
		return nil, err
	}

	recID := -1
	for i := 0; i < 2; i++ {
		v := byte(i + 27)
		sig := make([]byte, 65)
		copy(sig, signature)
		sig[64] = v
		pubKeyRecovered, err := crypto.SigToPub(hash[:], sig)
		if err == nil && pubKeyRecovered != nil {
			pubKeyBytes := crypto.FromECDSAPub(pubKeyRecovered)
			expectedPubKeyBytes := crypto.FromECDSAPub(publicKey)
			if bytes.Equal(pubKeyBytes, expectedPubKeyBytes) {
				recID = i
				break
			}
		}
	}

	if recID == -1 {
		return nil, errors.New("failed to recover public key")
	}

	v := byte(recID + 27 + int(chainID)*2 + 8)

	sig := make([]byte, 65)
	copy(sig, signature)
	sig[64] = v

	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return nil, err
	}

	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return signedTxBytes, nil
}

func parseDERSignature(der []byte) (r, s *big.Int, err error) {
	var sig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal DER signature: %w", err)
	}
	return sig.R, sig.S, nil
}

func parsePublicKeyDER(pubKeyDER []byte) (*ecdsa.PublicKey, error) {
	var spki subjectPublicKeyInfo
	_, err := asn1.Unmarshal(pubKeyDER, &spki)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal SubjectPublicKeyInfo: %w", err)
	}

	expectedOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	if !spki.Algorithm.Algorithm.Equal(expectedOID) {
		return nil, errors.New("unexpected public key algorithm")
	}

	var curveOID asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal curve OID: %w", err)
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

func (w *kmsWallet) getKeyNameForAddress(_ context.Context, address ethtypes.Address0xHex) (string, error) {
	w.mux.Lock()
	defer w.mux.Unlock()
	if keyName, exists := w.addressToKeyName[common.Address(address)]; exists {
		return keyName, nil
	}
	return "", errors.New("key name not found for the address")
}

func (w *kmsWallet) getPublicKeyForKeyName(ctx context.Context, keyName string) (*ecdsa.PublicKey, error) {
	input := &kms.GetPublicKeyInput{
		KeyId: aws.String(keyName),
	}
	output, err := w.kmsClient.GetPublicKey(ctx, input)
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

func (w *kmsWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if !w.conf.RemoteSign {
		r, err := w.CreateSecret(ctx, password, privateKeyHex)
		return ethsigner.CreateWalletResponse{
			Address: r.String(),
		}, err

	}

	return w.CreateKey(ctx, privateKeyHex)

}

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

func (w *kmsWallet) storeKeyPairSecret(ctx context.Context, keypair *secp256k1.KeyPair) error {
	secretName := strings.TrimPrefix(keypair.Address.String(), "0x")

	// Attempt to create the secret
	createInput := &secretsmanager.CreateSecretInput{
		Name:         aws.String(secretName),
		SecretBinary: keypair.PrivateKeyBytes(),
	}

	_, err := w.secretsClient.CreateSecret(ctx, createInput)
	if err == nil {
		return nil
	}

	var resourceExistsErr *secretsmanagertypes.ResourceExistsException
	if errors.As(err, &resourceExistsErr) {
		putInput := &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretName),
			SecretBinary: keypair.PrivateKeyBytes(),
		}

		_, putErr := w.secretsClient.PutSecretValue(ctx, putInput)
		if putErr != nil {
			return fmt.Errorf("failed to update existing secret '%s': %w", secretName, putErr)
		}
		return nil
	}

	// For other errors, return them
	return fmt.Errorf("failed to create secret '%s': %w", secretName, err)
}

func (w *kmsWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	input := &kms.CreateKeyInput{
		KeySpec:  kmstypes.KeySpecEccSecgP256k1,
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		Origin:   kmstypes.OriginTypeAwsKms,
	}
	output, err := w.kmsClient.CreateKey(ctx, input)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to create key: %w", err)
	}

	keyName := *output.KeyMetadata.KeyId

	pubKey, err := w.getPublicKeyForKeyName(ctx, keyName)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to get public key: %w", err)
	}

	address := crypto.PubkeyToAddress(*pubKey)

	w.mux.Lock()
	w.addressToKeyName[address] = keyName
	w.mux.Unlock()

	log.L(ctx).Debugf("AWS KMS: Created key %s with address %s", keyName, address.Hex())

	return ethsigner.CreateWalletResponse{
		Address: address.Hex(),
		KeyName: strings.TrimPrefix(address.Hex(), "0x"),
	}, nil
}

func (w *kmsWallet) AddMappingKeyAddress(key string, address string) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return errors.New("mapping feature not enabled")
	}
	w.mux.Lock()
	defer w.mux.Unlock()
	w.addressToKeyName[common.HexToAddress(address)] = key
	return nil
}

func (w *kmsWallet) Close() error {
	if w.stopRefresh != nil {
		close(w.stopRefresh)
	}
	return nil
}

func (w *kmsWallet) startRefreshLoop(ctx context.Context) {
	if !w.conf.MappingKeyAddress.Enabled || !w.conf.MappingKeyAddress.Refresh.Enabled {
		return
	}

	if w.conf.MappingKeyAddress.Refresh.Interval <= 0 {
		return
	}

	w.stopRefresh = make(chan struct{})

	go func() {
		ticker := time.NewTicker(w.conf.MappingKeyAddress.Refresh.Interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := w.refreshAddressToKeyNameMapping(ctx); err != nil {
					log.L(ctx).Errorf("Failed to refresh address-to-keyName mapping: %v", err)
				}
			case <-w.stopRefresh:
				return
			}
		}
	}()
}

func (w *kmsWallet) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	key := from.String()
	item := w.signerCache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		privateKey, err := w.getLocalPrivateKey(ctx, from)
		if err != nil {
			return nil, err
		}
		w.signerCache.Set(key, privateKey, w.signerCacheTTL)
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	return ethsigner.SignTypedDataV4(ctx, keypair, payload)
}

func (w *kmsWallet) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	w.mux.Lock()
	defer w.mux.Unlock()
	accounts := make([]*ethtypes.Address0xHex, 0, len(w.addressToKeyName))
	for address := range w.addressToKeyName {
		addr := ethtypes.Address0xHex(address)
		accounts = append(accounts, &addr)
	}
	return accounts, nil
}

func (w *kmsWallet) Refresh(ctx context.Context) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return nil
	}
	return w.refreshAddressToKeyNameMapping(ctx)
}

func (w *kmsWallet) refreshAddressToKeyNameMapping(ctx context.Context) error {
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

			keyDesc, err := w.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
				KeyId: aws.String(keyID),
			})
			if err != nil {
				log.L(ctx).Errorf("AWS KMS: failed to describe key %s: %v", keyID, err)
				continue
			}

			if keyDesc.KeyMetadata.KeyUsage != kmstypes.KeyUsageTypeSignVerify {
				continue
			}

			if keyDesc.KeyMetadata.KeySpec != kmstypes.KeySpecEccSecgP256k1 {
				continue
			}

			pubKey, err := w.getPublicKeyForKeyName(ctx, keyID)
			if err != nil {
				log.L(ctx).Errorf("AWS KMS: failed to get public key for key %s: %v", keyID, err)
				continue
			}

			address := crypto.PubkeyToAddress(*pubKey)

			w.mux.Lock()
			w.addressToKeyName[address] = keyID
			w.mux.Unlock()

			log.L(ctx).Debugf("AWS KMS: Mapped address %s to key %s", address.Hex(), keyID)
		}

		if output.Truncated {
			nextToken = output.NextMarker
		} else {
			break
		}
	}

	log.L(ctx).Debugf("AWS KMS: Updated %d address mappings", len(w.addressToKeyName))

	return nil
}
