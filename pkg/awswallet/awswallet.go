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
	"crypto/sha256"
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

	// Cria uma instância de KeyPair a partir da chave privada
	keypair, err := secp256k1.NewSecp256k1KeyPair(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create KeyPair: %w", err)
	}

	// Usa o KeyPair para assinar a transação
	signedTx, err := txn.Sign(keypair, chainID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	log.L(ctx).Debugf("AWS Secrets - Local Sign - Chain ID: %d - From: %s, Signed transaction", chainID, key)

	return signedTx, nil
}

// getLocalPrivateKey retrieves the private key from Secrets Manager or MongoDB.
func (w *kmsWallet) getLocalPrivateKey(ctx context.Context, address ethtypes.Address0xHex) ([]byte, error) {
	privateKeyData, err := w.getSecretsValue(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("AWS Secrets: failed to retrieve private key: %w", err)
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

// getSecretsValue retrieves the local data key from Secrets Manager.
func (w *kmsWallet) getSecretsValue(ctx context.Context, address ethtypes.Address0xHex) ([]byte, error) {
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

	return privateKeyData, nil
}

// RemoteSign signs a transaction using AWS KMS.
func (w *kmsWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	// Serialize the unsigned transaction for logging/debugging
	unsignedTxnJSON, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from common.Address
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	fmt.Printf("AWS KMS - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction: %s\n", chainID, key, string(unsignedTxnJSON))

	// Create the Ethereum transaction object
	toAddress := common.HexToAddress(txn.To.String())
	tx := types.NewTransaction(
		txn.Nonce.Uint64(),
		toAddress,
		txn.Value.BigInt(),
		txn.GasLimit.Uint64(),
		txn.GasPrice.BigInt(),
		txn.Data,
	)

	// Get the associated KMS key ID
	keyID, err := w.getKeyIDFromMongoDB(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed: %w", err)
	}

	transactOpts, err := NewAwsKmsTransactorWithChainIDCtx(ctx, w.kmsClient, keyID, big.NewInt(chainID))
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed: %w", err)
	}

	// Apply the signature to the transaction
	signedTx, err := transactOpts.Signer(transactOpts.From, tx)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed to apply signature to transaction: %w", err)
	}

	// Serialize the signed transaction
	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed to marshal signed transaction: %w", err)
	}

	return signedTxBytes, nil
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

	transactOpts, err := NewAwsKmsTransactorWithChainIDCtx(ctx, w.kmsClient, keyID, big.NewInt(chainID))
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed: %w", err)
	}

	toAddress := common.HexToAddress(txn.To.String())
	tx := types.NewTransaction(
		txn.Nonce.Uint64(),
		toAddress,
		txn.Value.BigInt(),
		txn.GasLimit.Uint64(),
		txn.GasPrice.BigInt(),
		txn.Data,
	)

	// Apply the signature to the transaction
	signedTx, err := transactOpts.Signer(transactOpts.From, tx)
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed to apply signature to transaction: %w", err)
	}

	// Serialize the signed transaction
	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("AWS KMS Sign operation failed to marshal signed transaction: %w", err)
	}

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
