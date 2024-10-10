// Copyright © 2024 Willian Patrick dos Santos
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

package awskms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
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
	"github.com/aws/aws-sdk-go-v2/credentials"
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
	AddMappingKeyAddress(key string, address string) error
	Initialize(ctx context.Context) error
	Close() error
	// Adicionado para assinatura de mensagens
	RemoteSignMessage(ctx context.Context, msg []byte, keyID string) ([]byte, error)
	VerifySignature(msg []byte, sig []byte, keyID string) (bool, error)
}

// kmsWallet implements the Wallet interface using AWS KMS.
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

// Initialize starts the refresh loop if mapping is enabled.
func (w *kmsWallet) Initialize(ctx context.Context) error {
	if w.conf.MappingKeyAddress.Enabled && w.conf.MappingKeyAddress.Refresh.Enabled {
		w.startRefreshLoop(ctx)
	}
	return nil
}

// Sign decides whether to perform local or remote signing based on configuration.
func (w *kmsWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if !w.conf.RemoteSign {
		return w.LocalSign(ctx, txn, chainID)
	}
	return w.RemoteSign(ctx, txn, chainID)
}

// LocalSign signs the transaction locally using the stored private key.
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
	log.L(ctx).Debugf("AWS KMS - Local Sign - Chain ID: %d - From: %s, Unsigned transaction: %s", chainID, key, string(unsignedTxnJSON))

	var privateKeyHex string
	item := w.signerCache.Get(key)
	if item != nil && !item.Expired() {
		item.Extend(w.signerCacheTTL)
		w.mux.Lock()
		privateKeyHex = item.Value().(string)
		w.mux.Unlock()
	} else {
		privateKeyHex, err = w.getLocalPrivateKey(ctx, from)
		if err != nil {
			return nil, err
		}
		w.signerCache.Set(key, privateKeyHex, w.signerCacheTTL)
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
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

// getLocalPrivateKey retrieves the local private key from Secrets Manager.
func (w *kmsWallet) getLocalPrivateKey(ctx context.Context, address ethtypes.Address0xHex) (string, error) {
	addr := common.Address(address).Hex()
	item := w.signerCache.Get(addr)
	if item != nil && !item.Expired() {
		privateKeyHex := item.Value().(string)
		return privateKeyHex, nil
	}

	secretName := strings.TrimPrefix(addr, "0x")
	getSecretInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(strings.ToLower(secretName)),
	}

	// Use a separate context with timeout for Secrets Manager operation
	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	secretValue, err := w.secretsClient.GetSecretValue(secretsCtx, getSecretInput)
	if err != nil {
		return "", fmt.Errorf("AWS KMS: failed to retrieve secret '%s': %w", secretName, err)
	}

	privateKeyHex := strings.TrimPrefix(*secretValue.SecretString, "0x")
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("AWS KMS: failed to decode private key hex: %w", err)
	}

	// Verify that the private key is valid
	_, err = crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return "", fmt.Errorf("AWS KMS: failed to parse ECDSA private key: %w", err)
	}

	w.signerCache.Set(addr, privateKeyHex, w.conf.LocalSign.Cache.TTL)

	return privateKeyHex, nil
}

// RemoteSign signs the transaction using AWS KMS.
func (w *kmsWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	// Clone the context with a timeout to prevent premature cancellation
	kmsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	// Marshal the transaction
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

	keyName, err := w.getKeyNameForAddress(ctx, from)
	if err != nil {
		return nil, err
	}

	// Prepare the SignInput for AWS KMS
	signInput := &kms.SignInput{
		KeyId:            aws.String(keyName),
		Message:          sha256Hash[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	// Call AWS KMS to sign the SHA-256 hash using the separate context
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

// computeRecoveryID computes the recovery ID (v) needed for the signature.
func computeRecoveryID(msgHash []byte, r, s *big.Int, w *kmsWallet, keyName string) (byte, error) {
	signatureRS := make([]byte, 64)
	copy(signatureRS[:32], padBytes(r.Bytes(), 32))
	copy(signatureRS[32:], padBytes(s.Bytes(), 32))

	// Retrieve the public key bytes
	publicKey, err := w.getPublicKeyForKeyName(context.Background(), keyName)
	if err != nil {
		return 0, err
	}
	expectedPubKeyBytes := crypto.FromECDSAPub(publicKey)

	// Try recovery IDs 0 and 1
	for recoveryID := 0; recoveryID < 2; recoveryID++ {
		sig := make([]byte, 65)
		copy(sig[:64], signatureRS)
		sig[64] = byte(recoveryID)

		// Recover public key
		pubKeyRecovered, err := crypto.SigToPub(msgHash, sig)
		if err != nil {
			continue
		}
		pubKeyRecoveredBytes := crypto.FromECDSAPub(pubKeyRecovered)

		if bytes.Equal(pubKeyRecoveredBytes, expectedPubKeyBytes) {
			return byte(recoveryID), nil
		}
	}

	return 0, errors.New("failed to compute recovery ID")
}

// padBytes pads the byte slice to the specified length
func padBytes(slice []byte, length int) []byte {
	if len(slice) >= length {
		return slice
	}
	padded := make([]byte, length)
	copy(padded[length-len(slice):], slice)
	return padded
}

// RemoteSignMessage signs a message using AWS KMS and returns the signature.
func (w *kmsWallet) RemoteSignMessage(ctx context.Context, msg []byte, keyID string) ([]byte, error) {
	// Criar contexto com timeout
	kmsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	// Calcular SHA-256 do hash da mensagem
	sha256Hash := sha256.Sum256(msg)

	// Preparar entrada para assinatura
	signInput := &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          sha256Hash[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	// Chamar AWS KMS para assinar
	signOutput, err := w.kmsClient.Sign(kmsCtx, signInput)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed: %w", err)
	}

	derSignature := signOutput.Signature

	// Parsear assinatura DER para r e s
	r, s, err := parseDERSignature(derSignature)
	if err != nil {
		return nil, err
	}

	// Ajustar s para ser <= half curve order
	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	// Padronizar r e s para 32 bytes cada
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	signature := make([]byte, 64)
	copy(signature, rPadded)
	copy(signature[32:], sPadded)

	// Tentar recuperar a chave pública com v=27 e v=28
	publicKey, err := w.getPublicKeyForKeyName(ctx, keyID)
	if err != nil {
		return nil, err
	}
	expectedPubKeyBytes := crypto.FromECDSAPub(publicKey)

	var v byte
	found := false
	for recID := 0; recID < 2; recID++ {
		v = byte(recID + 27)
		sig := make([]byte, 65)
		copy(sig, signature)
		sig[64] = v

		// Recuperar a chave pública usando o SHA-256 hash
		pubKeyRecovered, err := crypto.SigToPub(sha256Hash[:], sig)
		if err == nil && pubKeyRecovered != nil {
			pubKeyBytes := crypto.FromECDSAPub(pubKeyRecovered)
			if bytes.Equal(pubKeyBytes, expectedPubKeyBytes) {
				found = true
				break
			}
		}
	}

	if !found {
		return nil, errors.New("failed to recover public key")
	}

	// Assegurar que v está correto (27 ou 28)
	// Para assinaturas de mensagens, v geralmente é 27 ou 28
	// Não é necessário ajustá-lo para EIP-155
	sig := make([]byte, 65)
	copy(sig, signature)
	sig[64] = v

	return sig, nil
}

// VerifySignature verifica se a assinatura é válida para a mensagem e a chave pública fornecida.
func (w *kmsWallet) VerifySignature(msg []byte, sig []byte, keyID string) (bool, error) {
	// Calcular SHA-256 do hash da mensagem
	sha256Hash := sha256.Sum256(msg)

	// Recuperar a chave pública
	publicKey, err := w.getPublicKeyForKeyName(context.Background(), keyID)
	if err != nil {
		return false, err
	}

	// Dividir a assinatura em r, s e v
	if len(sig) != 65 {
		return false, errors.New("invalid signature length")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[64]

	// Ajustar s se necessário
	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	// Tentar recuperar a chave pública com v=27 e v=28
	var found bool
	for recID := 0; recID < 2; recID++ {
		v = byte(recID + 27)
		sigTemp := make([]byte, 65)
		copy(sigTemp, sig[:64])
		sigTemp[64] = v

		pubKeyRecovered, err := crypto.SigToPub(sha256Hash[:], sigTemp)
		if err == nil && pubKeyRecovered != nil {
			pubKeyBytes := crypto.FromECDSAPub(pubKeyRecovered)
			expectedPubKeyBytes := crypto.FromECDSAPub(publicKey)
			if bytes.Equal(pubKeyBytes, expectedPubKeyBytes) {
				found = true
				break
			}
		}
	}

	if !found {
		return false, errors.New("failed to verify signature with the provided public key")
	}

	// Verificar a assinatura usando a chave pública
	verified := ecdsa.Verify(publicKey, sha256Hash[:], r, s)
	return verified, nil
}

// parseDERSignature parses a DER-encoded ECDSA signature and returns r and s values.
func parseDERSignature(der []byte) (r, s *big.Int, err error) {
	var sig struct {
		R, S *big.Int
	}
	_, err = asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse DER signature: %w", err)
	}
	return sig.R, sig.S, nil
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

// getKeyNameForAddress retrieves the key name associated with an Ethereum address.
func (w *kmsWallet) getKeyNameForAddress(ctx context.Context, address ethtypes.Address0xHex) (string, error) {
	w.mux.Lock()
	if keyName, exists := w.addressToKeyName[common.Address(address)]; exists {
		w.mux.Unlock()
		return keyName, nil
	}
	w.mux.Unlock()

	// Attempt to refresh the mapping
	if err := w.refreshAddressToKeyNameMapping(ctx); err != nil {
		return "", err
	}

	w.mux.Lock()
	defer w.mux.Unlock()
	if keyName, exists := w.addressToKeyName[common.Address(address)]; exists {
		return keyName, nil
	}
	return "", fmt.Errorf("key name not found for the address %s", address)
}

// getPublicKeyForKeyName retrieves the public key associated with a KMS key name.
func (w *kmsWallet) getPublicKeyForKeyName(ctx context.Context, keyName string) (*ecdsa.PublicKey, error) {
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

// CreateWallet creates a new wallet either locally or remotely based on configuration.
func (w *kmsWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if !w.conf.RemoteSign {
		r, err := w.CreateSecret(ctx, password, privateKeyHex)
		return ethsigner.CreateWalletResponse{
			Address: r.String(),
		}, err
	}

	return w.CreateKey(ctx, privateKeyHex)
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
	secretName := strings.TrimPrefix(keypair.Address.String(), "0x")

	// Convert the private key bytes to a hex-encoded string
	privateKeyHex := hex.EncodeToString(keypair.PrivateKeyBytes())

	// Attempt to create the secret
	createInput := &secretsmanager.CreateSecretInput{
		Name:         aws.String(strings.ToLower(secretName)),
		SecretString: aws.String(privateKeyHex),
	}

	// Clone the context with a timeout
	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	_, err := w.secretsClient.CreateSecret(secretsCtx, createInput)
	if err == nil {
		// Secret created successfully
		return nil
	}

	// Handle ResourceExistsException using smithy-go
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr.ErrorCode() == "ResourceExistsException" {
		// Secret already exists, proceed to update it
		putInput := &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(strings.ToLower(secretName)),
			SecretString: aws.String(privateKeyHex),
		}

		_, putErr := w.secretsClient.PutSecretValue(secretsCtx, putInput)
		if putErr != nil {
			return fmt.Errorf("failed to update existing secret '%s': %w", secretName, putErr)
		}
		return nil
	}

	// For other errors, return them
	return fmt.Errorf("failed to create secret '%s': %w", secretName, err)
}

// CreateKey creates a new KMS key and associates it with an Ethereum address via tagging.
// Nota: Essa assinatura não será válida para transações Ethereum devido à incompatibilidade de hashes.
func (w *kmsWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	// Clone the context com timeout
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

	keyName := *output.KeyMetadata.KeyId

	pubKey, err := w.getPublicKeyForKeyName(ctx, keyName)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to get public key: %w", err)
	}

	address := crypto.PubkeyToAddress(*pubKey)

	// Clone the context com timeout para tagging
	tagCtx, cancelTag := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancelTag()

	// Adicionar a tag ao recurso KMS para mapeamento
	_, err = w.kmsClient.TagResource(tagCtx, &kms.TagResourceInput{
		KeyId: aws.String(keyName),
		Tags: []kmstypes.Tag{
			{
				TagKey:   aws.String("EthereumAddress"),
				TagValue: aws.String(address.Hex()),
			},
		},
	})
	if err != nil {
		return ethsigner.CreateWalletResponse{}, fmt.Errorf("AWS KMS: failed to add tag to key: %w", err)
	}

	w.mux.Lock()
	w.addressToKeyName[address] = keyName
	w.mux.Unlock()

	log.L(ctx).Debugf("AWS KMS: Created key %s with address %s", keyName, address.Hex())

	return ethsigner.CreateWalletResponse{
		Address: address.Hex(),
		KeyName: strings.TrimPrefix(address.Hex(), "0x"),
	}, nil
}

// AddMappingKeyAddress manually adds a mapping between a key and an Ethereum address.
func (w *kmsWallet) AddMappingKeyAddress(key string, address string) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return errors.New("mapping feature not enabled")
	}
	w.mux.Lock()
	defer w.mux.Unlock()
	w.addressToKeyName[common.HexToAddress(address)] = key
	return nil
}

// Close stops the refresh loop if it's running.
func (w *kmsWallet) Close() error {
	if w.stopRefresh != nil {
		close(w.stopRefresh)
	}
	return nil
}

// startRefreshLoop starts a background goroutine to periodically refresh the address-to-keyName mapping.
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
				// Use a separate context com timeout para cada operação de refresh
				refreshCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
				err := w.refreshAddressToKeyNameMapping(refreshCtx)
				cancel()
				if err != nil {
					log.L(ctx).Errorf("Failed to refresh address-to-keyName mapping: %v", err)
				}
			case <-w.stopRefresh:
				return
			}
		}
	}()
}

// SignTypedDataV4 signs EIP-712 typed data using the stored private key.
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

	privateKeyBytes, err := hex.DecodeString(privateKey)
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
	w.mux.Lock()
	defer w.mux.Unlock()
	accounts := make([]*ethtypes.Address0xHex, 0, len(w.addressToKeyName))
	for address := range w.addressToKeyName {
		addr := ethtypes.Address0xHex(address)
		accounts = append(accounts, &addr)
	}
	return accounts, nil
}

// Refresh manually triggers the refresh of the address-to-keyName mapping.
func (w *kmsWallet) Refresh(ctx context.Context) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return nil
	}
	// Use a separate context com timeout para refresh
	refreshCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()
	return w.refreshAddressToKeyNameMapping(refreshCtx)
}

// refreshAddressToKeyNameMapping updates the mapping between Ethereum addresses and KMS key names by reading tags.
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

			// Get the tags of the key
			tagsOutput, err := w.kmsClient.ListResourceTags(ctx, &kms.ListResourceTagsInput{
				KeyId: aws.String(keyID),
			})
			if err != nil {
				log.L(ctx).Errorf("AWS KMS: failed to list tags for key %s: %v", keyID, err)
				continue
			}

			var address common.Address
			for _, tag := range tagsOutput.Tags {
				if *tag.TagKey == "EthereumAddress" {
					address = common.HexToAddress(*tag.TagValue)
					break
				}
			}

			if (address == common.Address{}) {
				// Se não há tag EthereumAddress, pular esta chave
				continue
			}

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
