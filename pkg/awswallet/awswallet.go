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
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Wallet interface defines the necessary methods for the KMS wallet.
type Wallet interface {
	ethsigner.WalletTypedData
	Initialize(ctx context.Context) error
	Close() error
}

// kmsWallet implements the Wallet interface using AWS KMS.
type kmsWallet struct {
	conf              Config
	secretsClient     *secretsmanager.Client
	kmsClient         *kms.Client
	walletsCollection *mongo.Collection
}

type WalletData struct {
	Address string `bson:"address"`
	KeyID   string `bson:"keyId"`
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

	if conf.Region != "" {
		log.L(ctx).Debugf("AWS: Region config: %s", conf.Region)
	}

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

	if w.conf.UseKMS {
		log.L(ctx).Debugf("AWS KMS: Enabled")
		w.kmsClient = kms.NewFromConfig(awsCfg)
	}

	if w.conf.UseSecrets {
		log.L(ctx).Debugf("AWS Secrets: Enabled")
		w.secretsClient = secretsmanager.NewFromConfig(awsCfg)
	}

	if !w.conf.UseSecrets && w.conf.UseKMS {
		if w.conf.MongoDB.ConnectionString == "" {
			return nil, fmt.Errorf("MongoDB Config required for operations use only KMS")
		}
		clientOptions := options.Client().
			ApplyURI(w.conf.MongoDB.ConnectionString).
			SetConnectTimeout(30 * time.Second).
			SetSocketTimeout(30 * time.Second)

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		mongoClient, err := mongo.Connect(ctx, clientOptions)
		if err != nil {
			return nil, fmt.Errorf("MongoDB connection error: %v", err)
		}

		err = mongoClient.Ping(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("MongoDB ping error: %v", err)
		}

		log.L(ctx).Debugf("MongoDB connection established successfully.")

		database := mongoClient.Database(w.conf.MongoDB.DatabaseName)
		w.walletsCollection = database.Collection(w.conf.MongoDB.CollectionName)
	}

	if w.conf.UseSecrets && w.conf.UseKMS {
		log.L(ctx).Debugf("AWS Secrets & KMS Flow - Enabled")
	}

	return w, nil
}

// Initialize starts the refresh loop if mapping is enabled.
func (w *kmsWallet) Initialize(ctx context.Context) error {
	return nil
}

// Sign decides whether to perform local or remote signing based on configuration.
func (w *kmsWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if w.conf.UseKMS && !w.conf.UseSecrets {
		return w.RemoteSign(ctx, txn, chainID)
	} else if w.conf.UseSecrets && !w.conf.UseKMS {
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
	if !w.conf.UseSecrets {
		return nil, errors.New("AWS Secrets Manager is not enabled")
	}

	addr := address.String()
	if w.conf.EncryptSecrets {
		addr = w.hashAddress(addr)
		log.L(ctx).Debugf("AWS Secrets - KeyName: '%s'", strings.ToLower(strings.TrimPrefix(addr, "0x")))
	}
	getSecretInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(strings.ToLower(strings.TrimPrefix(addr, "0x"))),
	}

	// Retrieve secret with a timeout.
	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	secretValue, err := w.secretsClient.GetSecretValue(secretsCtx, getSecretInput)
	if err != nil {
		return nil, fmt.Errorf("AWS Secrets: failed to retrieve wallet '%s': %w", addr, err)
	}

	var privateKeyData []byte

	switch {
	case secretValue.SecretBinary != nil:
		privateKeyData = secretValue.SecretBinary
	case secretValue.SecretString != nil:
		privateKeyData = []byte(*secretValue.SecretString)
	default:
		return nil, fmt.Errorf("AWS Secrets: secret for wallet '%s' has no data", addr)
	}

	if w.conf.EncryptSecrets {
		privateKeyData, err = w.decryptData(privateKeyData, addr)
		if err != nil {
			return nil, fmt.Errorf("AWS Secrets: failed to decrypt private key: %w", err)
		}
	}

	// Check if the private key is in hex string format and decode if necessary
	if len(privateKeyData) != 32 {
		privateKeyString := strings.TrimSpace(string(privateKeyData))
		// Remove possible "0x" prefix
		privateKeyString = strings.TrimPrefix(privateKeyString, "0x")
		privateKeyData, err = hex.DecodeString(privateKeyString)
		if err != nil {
			return nil, fmt.Errorf("AWS Secrets: failed to decode hex private key: %w", err)
		}
	}

	if len(privateKeyData) != 32 {
		return nil, fmt.Errorf("AWS Secrets: invalid private key length: expected 32 bytes, got %d", len(privateKeyData))
	}

	_, err = crypto.ToECDSA(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("AWS Secrets: invalid ECDSA private key: %w", err)
	}

	return privateKeyData, nil
}

// RemoteSign signs the transaction using AWS KMS.
func (w *kmsWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if !w.conf.UseKMS {
		return nil, errors.New("AWS KMS is not enabled")
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
	log.L(ctx).Debugf("AWS KMS - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction: %s", chainID, key, string(unsignedTxnJSON))

	signer := types.NewEIP155Signer(big.NewInt(chainID))
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    txn.Nonce.Uint64(),
		To:       (*common.Address)(txn.To),
		Value:    txn.Value.BigInt(),
		Gas:      txn.GasLimit.Uint64(),
		GasPrice: txn.GasPrice.BigInt(),
		Data:     txn.Data,
	})

	keyID, err := w.getKeyIDFromMongoDB(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("MongoDB operation failed: %w", err)
	}

	// Calcula o hash da transação Ethereum usando Keccak-256.
	ethHash := signer.Hash(tx)

	// AWS KMS espera um SHA-256 hash, então fazemos um hashing adicional em cima do Keccak-256.
	sha256Digest := sha256.Sum256(ethHash[:])

	signInput := &kms.SignInput{
		KeyId:            aws.String(keyID),
		Message:          sha256Digest[:],
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256,
	}

	kmsCtx, cancel := context.WithTimeout(ctx, AWSKMSTimeout)
	defer cancel()
	signOutput, err := w.kmsClient.Sign(kmsCtx, signInput)
	if err != nil {
		return nil, fmt.Errorf("Sign operation failed: %w", err)
	}

	signatureDER := signOutput.Signature
	log.L(ctx).Debugf("AWS KMS - Remote Sign - Signature (DER): %s", hex.EncodeToString(signatureDER))

	// Extrair r e s da assinatura DER
	var ecdsaSig struct {
		R, S *big.Int
	}
	if _, err := asn1.Unmarshal(signatureDER, &ecdsaSig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ECDSA signature: %w", err)
	}
	r, s := ecdsaSig.R, ecdsaSig.S

	// Garante que s esteja na metade inferior da ordem do grupo
	curveOrder := crypto.S256().Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(curveOrder, s)
	}

	vBase := byte(chainID*2 + 35)
	var finalSig []byte

	// Recupera a chave pública para comparação
	publicKey, err := w.GetPubKeyCtx(ctx, keyID)
	if err != nil {
		return nil, err
	}

	// Determina `recID` iterando sobre possíveis valores (0 e 1) para o ajuste de v
	for i := 0; i < 2; i++ {
		testV := vBase + byte(i)
		rBytes := common.LeftPadBytes(r.Bytes(), 32)
		sBytes := common.LeftPadBytes(s.Bytes(), 32)
		sig := append(append(rBytes, sBytes...), testV)

		// Recupera a chave pública a partir da assinatura
		recoveredPubKey, err := crypto.Ecrecover(ethHash[:], sig)
		if err != nil {
			log.L(ctx).Debugf("AWS KMS - Remote Sign - Error: %s", err)
			continue
		}

		// Verifica se a chave pública recuperada é não compactada e possui 65 bytes com prefixo 0x04
		if len(recoveredPubKey) != 65 || recoveredPubKey[0] != 0x04 {
			continue
		}

		// Extrai coordenadas X e Y da chave pública recuperada
		recoveredX := new(big.Int).SetBytes(recoveredPubKey[1:33])
		recoveredY := new(big.Int).SetBytes(recoveredPubKey[33:65])
		recoveredPublicKey := ecdsa.PublicKey{Curve: crypto.S256(), X: recoveredX, Y: recoveredY}

		// Compara a chave pública recuperada com a chave pública armazenada
		if recoveredPublicKey.X.Cmp(publicKey.X) == 0 && recoveredPublicKey.Y.Cmp(publicKey.Y) == 0 {
			finalSig = sig
			log.L(ctx).Debugf("AWS KMS - Remote Sign - finalSig")
			break
		}
	}

	// Caso `recID` exato não seja encontrado, usa `recID=0` como fallback
	if finalSig == nil {
		rBytes := common.LeftPadBytes(r.Bytes(), 32)
		sBytes := common.LeftPadBytes(s.Bytes(), 32)
		finalSig = append(append(rBytes, sBytes...), vBase)
	}

	log.L(ctx).Debugf("AWS KMS - Remote Sign - Signature (R,S,V): %s", hex.EncodeToString(finalSig))

	signedTx, err := tx.WithSignature(signer, finalSig)
	if err != nil {
		return nil, err
	}

	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signedTxJSON, err := json.Marshal(signedTx)
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AWS KMS - Remote Sign - Chain ID: %d - From: %s, Send RPC Transaction With Signature: %s", chainID, key, hex.EncodeToString(signedTxJSON))

	return signedTxBytes, nil
}

type asn1EcPublicKey struct {
	EcPublicKeyInfo asn1EcPublicKeyInfo
	PublicKey       asn1.BitString
}

type asn1EcPublicKeyInfo struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

func (w *kmsWallet) GetPubKeyCtx(ctx context.Context, kmskey string) (*ecdsa.PublicKey, error) {
	getPubKeyOutput, err := w.kmsClient.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(kmskey),
	})
	if err != nil {
		return nil, err
	}

	var asn1pubk asn1EcPublicKey
	_, err = asn1.Unmarshal(getPubKeyOutput.PublicKey, &asn1pubk)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := asn1pubk.PublicKey.Bytes
	pubkey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return pubkey, nil
}

// getKeyIDFromMongoDB retrieves the KeyId from MongoDB based on the Ethereum address
func (w *kmsWallet) getKeyIDFromMongoDB(ctx context.Context, address string) (string, error) {
	filter := bson.M{"Address": strings.ToLower(address)}
	var walletData struct{ KeyID string }
	err := w.walletsCollection.FindOne(ctx, filter).Decode(&walletData)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return "", fmt.Errorf("MongoDB: wallet not found for address %s", address)
		}
		return "", fmt.Errorf("MongoDB: query failed: %w", err)
	}

	if w.conf.EncryptSecrets {
		decryptedKeyID, errDecrypt := w.decryptData([]byte(walletData.KeyID), address)
		if errDecrypt != nil {
			return "", fmt.Errorf("failed to decrypt KeyID for address '%s': %w", address, errDecrypt)
		}
		return string(decryptedKeyID), nil
	}

	return walletData.KeyID, nil
}

// getKMSKeyIDFromSecrets retrieves the KMS KeyId associated with an Ethereum address from Secrets Manager.
func (w *kmsWallet) getKMSKeyIDFromSecrets(ctx context.Context, address ethtypes.Address0xHex) (string, error) {
	addr := common.Address(address).Hex()
	if w.conf.EncryptSecrets {
		addr = w.hashAddress(addr)
		log.L(ctx).Debugf("AWS Secrets - KeyName: '%s'", strings.ToLower(strings.TrimPrefix(addr, "0x")))
	}
	getSecretInput := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(strings.ToLower(strings.TrimPrefix(addr, "0x"))),
	}

	secretsCtx, cancel := context.WithTimeout(context.Background(), AWSKMSTimeout)
	defer cancel()

	secretValue, err := w.secretsClient.GetSecretValue(secretsCtx, getSecretInput)
	if err != nil {
		return "", fmt.Errorf("AWS KMS: failed to retrieve wallet address '%s': %w", addr, err)
	}

	keyID := string(secretValue.SecretBinary)
	if w.conf.EncryptSecrets {
		decryptedKeyID, errDecrypt := w.decryptData(secretValue.SecretBinary, addr)
		if errDecrypt != nil {
			return "", fmt.Errorf("AWS KMS: failed to decrypt KeyID for wallet address '%s': %w", addr, errDecrypt)
		}
		keyID = string(decryptedKeyID)
	}

	return keyID, nil
}

// RemoteSignWithSecrets signs the transaction using AWS KMS and Secrets Manager when both are active or both are inactive.
func (w *kmsWallet) RemoteSignWithSecrets(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	// KMS and Secrets are both active or both inactive (default behavior)
	if !w.conf.UseKMS || !w.conf.UseSecrets {
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

func (w *kmsWallet) Close() error {
	if w.walletsCollection != nil {
		return w.walletsCollection.Database().Client().Disconnect(context.Background())
	}
	return nil
}

func (w *kmsWallet) Refresh(ctx context.Context) error {
	return nil
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

func (w *kmsWallet) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	return nil, nil
}

func (w *kmsWallet) deriveKey(address string) []byte {
	input := strings.ToLower(strings.TrimPrefix(address, "0x") + w.conf.PrivateAddressKey)
	hash := sha256.Sum256([]byte(input))
	return hash[:]
}

func (w *kmsWallet) hashAddress(address string) string {
	return strings.ToLower(hex.EncodeToString(w.deriveKey(address)))
}

// decryptData decrypts the input ciphertext using AES-GCM with the given address as key material
func (w *kmsWallet) decryptData(ciphertext []byte, address string) ([]byte, error) {
	aesKey := w.deriveKey(address)

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES GCM mode: %w", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	data, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return data, nil
}
