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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type subjectPublicKeyInfo struct {
	Algorithm        algorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// Wallet interface defines the methods required for a wallet implementation.
type Wallet interface {
	ethsigner.WalletTypedData
	CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error)
	AddMappingKeyAddress(key string, address string) error
	Initialize(ctx context.Context) error
	Close() error
}

// kmsWallet implements the Wallet interface using AWS KMS.
type kmsWallet struct {
	conf             Config
	kmsClient        *kms.Client
	stopRefresh      chan struct{}
	addressToKeyName map[common.Address]string
	mux              sync.Mutex
}

// NewAWSKMSWallet initializes a new AWS KMS wallet.
func NewAWSKMSWallet(ctx context.Context, conf *Config) (Wallet, error) {
	w := &kmsWallet{
		conf: *conf,
	}

	var awsCfg aws.Config
	var err error

	// Use provided AWS credentials if available, otherwise use default credentials.
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

	// Verificar as credenciais usando STS
	stsClient := sts.NewFromConfig(awsCfg)
	callerIdentity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, fmt.Errorf("AWS KMS: failed to get caller identity: %w", err)
	}
	log.L(ctx).Debugf("AWS KMS: Successfully authenticated as %s", *callerIdentity.Arn)

	w.kmsClient = kms.NewFromConfig(awsCfg)
	w.addressToKeyName = make(map[common.Address]string)

	return w, nil
}

// Initialize sets up any necessary initialization for the wallet.
func (w *kmsWallet) Initialize(ctx context.Context) error {
	if w.conf.MappingKeyAddress.Enabled && w.conf.MappingKeyAddress.Refresh.Enabled {
		w.startRefreshLoop(ctx)
	}
	return nil
}

// Sign handles signing of transactions, delegating to remote signing.
func (w *kmsWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	return w.RemoteSign(ctx, txn, chainID)
}

// RemoteSign signs the transaction using AWS KMS.
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
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256, // Verifique se este é o algoritmo correto para secp256k1
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

	// Ensure 's' is in the lower half of the curve order
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

	// Combine rPadded and sPadded into a single signature slice.
	signature := make([]byte, 64)
	copy(signature, rPadded)
	copy(signature[32:], sPadded)

	// Recover the recovery ID (v)
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

	// Combine signature and v into sig slice.
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

// parseDERSignature parses a DER-encoded ECDSA signature.
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

	// Verificar se o algoritmo é id-ecPublicKey (1.2.840.10045.2.1)
	expectedOID := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1} // id-ecPublicKey
	if !spki.Algorithm.Algorithm.Equal(expectedOID) {
		return nil, errors.New("unexpected public key algorithm")
	}

	// Unmarshal Parameters para obter o OID da curva
	var curveOID asn1.ObjectIdentifier
	_, err = asn1.Unmarshal(spki.Algorithm.Parameters.FullBytes, &curveOID)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal curve OID: %w", err)
	}

	// Verificar se a curva é secp256k1 (1.3.132.0.10)
	secp256k1OID := asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	if !curveOID.Equal(secp256k1OID) {
		return nil, errors.New("unexpected public key curve")
	}

	// A chave pública está no formato uncompressed: 0x04 || X (32 bytes) || Y (32 bytes)
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

// getKeyNameForAddress retrieves the KeyId associated with the given Ethereum address.
func (w *kmsWallet) getKeyNameForAddress(_ context.Context, address ethtypes.Address0xHex) (string, error) {
	w.mux.Lock()
	defer w.mux.Unlock()
	if keyName, exists := w.addressToKeyName[common.Address(address)]; exists {
		return keyName, nil
	}
	return "", errors.New("key name not found for the address")
}

// getPublicKeyForKeyName retrieves the public key associated with the given KeyId.
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

// CreateWallet creates a new wallet, optionally importing a provided private key.
func (w *kmsWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	return w.CreateKey(ctx, privateKeyHex)
}

// CreateKey creates a new key in AWS KMS or imports an existing private key.
func (w *kmsWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if privateKeyHex != "" {
		address, keyName, err := w.ImportKey(ctx, privateKeyHex)
		if err != nil {
			return ethsigner.CreateWalletResponse{}, err
		}
		return ethsigner.CreateWalletResponse{
			Address: strings.TrimPrefix(address.String(), "0x"),
			KeyName: keyName,
		}, nil
	}

	// Create an asymmetric key in KMS
	input := &kms.CreateKeyInput{
		KeySpec:  kmstypes.KeySpecEccSecgP256k1,
		KeyUsage: kmstypes.KeyUsageTypeSignVerify,
		Origin:   kmstypes.OriginTypeAwsKms,
		Tags: []kmstypes.Tag{
			{
				TagKey:   aws.String("CreatedBy"),
				TagValue: aws.String("YourAppName"),
			},
		},
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
		Address: strings.TrimPrefix(address.Hex(), "0x"),
		KeyName: keyName,
	}, nil
}

// ImportKey attempts to import a private key. AWS KMS does not support importing private keys.
func (w *kmsWallet) ImportKey(ctx context.Context, privateKeyHex string) (ethtypes.Address0xHex, string, error) {
	privateKey, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return ethtypes.Address0xHex{}, "", err
	}

	privateKeyECDSA, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return ethtypes.Address0xHex{}, "", err
	}

	publicKeyECDSA := privateKeyECDSA.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	// AWS KMS does not support importing private keys directly.
	// Therefore, we return an error indicating that importing private keys is not supported.
	return ethtypes.Address0xHex(address), "", errors.New("importing private keys is not supported in AWS KMS")
}

// AddMappingKeyAddress adds a mapping between a keyName and an Ethereum address.
func (w *kmsWallet) AddMappingKeyAddress(key string, address string) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return errors.New("mapping feature not enabled")
	}
	w.mux.Lock()
	defer w.mux.Unlock()
	w.addressToKeyName[common.HexToAddress(address)] = key
	return nil
}

// Close gracefully shuts down the wallet, stopping any ongoing refresh loops.
func (w *kmsWallet) Close() error {
	if w.stopRefresh != nil {
		close(w.stopRefresh)
	}
	return nil
}

// startRefreshLoop starts a background loop to periodically refresh the address-to-keyName mapping.
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

// SignTypedDataV4 is not implemented for AWS KMS.
func (w *kmsWallet) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	return nil, errors.New("SignTypedDataV4 not implemented")
}

// GetAccounts retrieves all Ethereum addresses mapped to keys in AWS KMS.
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

// Refresh updates the address-to-keyName mapping.
func (w *kmsWallet) Refresh(ctx context.Context) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return nil
	}
	return w.refreshAddressToKeyNameMapping(ctx)
}

// refreshAddressToKeyNameMapping refreshes the mapping between Ethereum addresses and AWS KMS KeyIds.
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
