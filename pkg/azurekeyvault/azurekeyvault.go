// Copyright © 2024 Kaleido, Inc.
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

package azurekeyvault

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/karlseguin/ccache"
)

type Wallet interface {
	ethsigner.WalletTypedData
	CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethtypes.Address0xHex, error) // Add this method
}

func NewAzureKeyVaultWallet(ctx context.Context, conf *Config) (ww Wallet, err error) {
	w := &azWallet{
		conf: *conf,
	}

	cred, err := azidentity.NewClientSecretCredential(conf.TenantID, conf.ClientID, conf.ClientSecret, nil)
	if err != nil {
		return nil, err
	}

	client, err := azsecrets.NewClient(conf.VaultURL, cred, nil)
	if err != nil {
		return nil, err
	}

	keyClient, err := azkeys.NewClient(conf.VaultURL, cred, nil)
	if err != nil {
		return nil, err
	}

	maxSize := conf.Cache.MaxSize | int64(100)
	itemsToPrune := conf.Cache.ItemsToPrune | uint32(10)

	w.signerCache = ccache.New(ccache.Configure().MaxSize(maxSize).ItemsToPrune(itemsToPrune))
	w.Client = client
	w.KeyClient = keyClient
	return w, nil
}

type azWallet struct {
	conf           Config
	signerCache    *ccache.Cache
	signerCacheTTL time.Duration
	mux            sync.Mutex
	Client         *azsecrets.Client
	KeyClient      *azkeys.Client
}

func (w *azWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if !w.conf.RemoteSign {
		return w.LocalSign(ctx, txn, chainID)
	}
	return w.RemoteSign(ctx, txn, chainID)
}

func (w *azWallet) LocalSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AzureKeyVault - Local Sign - Chain ID: %d - From: %s, Unsigned transaction: %s", chainID, key, string(unsignedTxBytes))

	item := w.signerCache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		item.Extend(w.signerCacheTTL)
		w.mux.Lock()
		privateKey = item.Value().(string)
		w.mux.Unlock()
	} else {
		secretResp, err := w.Client.GetSecret(ctx, strings.TrimPrefix(key, "0x"), "", nil) // Use the address as the key name
		if err != nil {
			return nil, err
		}
		privateKey = *secretResp.Value
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

	signedTx, err := txn.Sign(keypair, chainID)
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AzureKeyVault - Local Sign - Chain ID: %d - From: %s, Signed transaction: %s", chainID, key, hex.EncodeToString(signedTx))

	return signedTx, nil
}

func (w *azWallet) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	key := from.String()
	item := w.signerCache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		secretResp, err := w.Client.GetSecret(ctx, strings.TrimPrefix(from.String(), "0x"), "", nil) // Use the address as the key name
		if err != nil {
			return nil, err
		}

		privateKey = *secretResp.Value
		w.signerCache.Set(key, privateKey, w.signerCacheTTL)
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	return ethsigner.SignTypedDataV4(ctx, keypair, payload)
}

func (w *azWallet) Initialize(ctx context.Context) error {
	return w.Refresh(ctx)
}

func (w *azWallet) GetAccounts(_ context.Context) ([]*ethtypes.Address0xHex, error) {
	return nil, nil
}

func (w *azWallet) Refresh(ctx context.Context) error {
	return nil
}

func (w *azWallet) Close() error {
	return nil
}

func (w *azWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethtypes.Address0xHex, error) {
	if !w.conf.RemoteSign {
		return w.CreateSecret(ctx, password, privateKeyHex)
	}
	return w.CreateKey(ctx, privateKeyHex)
}

func (w *azWallet) CreateSecret(ctx context.Context, password string, privateKeyHex string) (ethtypes.Address0xHex, error) {
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
	err = w.storeKeyPairInAzureKeyVault(ctx, keypair)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}
	return keypair.Address, nil
}

func (w *azWallet) storeKeyPairInAzureKeyVault(ctx context.Context, keypair *secp256k1.KeyPair) error {
	secretName := strings.TrimPrefix(keypair.Address.String(), "0x")
	secretValue := hex.EncodeToString(keypair.PrivateKeyBytes())
	parameters := azsecrets.SetSecretParameters{
		Value: to.Ptr(secretValue),
	}
	_, err := w.Client.SetSecret(ctx, secretName, parameters, nil)
	if err != nil {
		return err
	}
	return nil
}

func (w *azWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AzureKeyVault - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction: %s", chainID, key, string(unsignedTxBytes))

	// Calculate the message hash
	signer := types.NewEIP155Signer(big.NewInt(chainID))
	tx := types.NewTransaction(
		txn.Nonce.Uint64(),
		common.HexToAddress(txn.To.String()),
		txn.Value.BigInt(),
		txn.GasLimit.Uint64(),
		txn.GasPrice.BigInt(),
		txn.Data,
	)
	hash := signer.Hash(tx)

	signParameters := azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.JSONWebKeySignatureAlgorithmES256K),
		Value:     hash[:],
	}

	// Sign the digest using the key in Azure Key Vault
	signResult, err := w.KeyClient.Sign(ctx, strings.TrimPrefix(key, "0x"), "", signParameters, nil)
	if err != nil {
		return nil, err
	}

	signature := signResult.Result
	if len(signature) != 64 {
		return nil, errors.New("invalid signature length")
	}

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := byte(chainID*2 + 35 + 27)

	// Use the `ethereum` package to construct a proper signed transaction
	signedTx, err := tx.WithSignature(signer, append(append(r.Bytes(), s.Bytes()...), v))
	if err != nil {
		return nil, err
	}

	// RLP encode the signed transaction
	signedTxBytes, err := rlp.EncodeToBytes(signedTx)
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AzureKeyVault - Remote Sign - Chain ID: %d - From: %s, Signed transaction: %s", chainID, key, hex.EncodeToString(signedTxBytes))

	return signedTxBytes, nil
}

func (w *azWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethtypes.Address0xHex, error) {
	if privateKeyHex != "" {
		return w.ImportKey(ctx, privateKeyHex)
	}

	keyParams := azkeys.CreateKeyParameters{
		Kty:   to.Ptr(azkeys.JSONWebKeyTypeEC),
		Curve: to.Ptr(azkeys.JSONWebKeyCurveNameP256K),
		KeyOps: []*azkeys.JSONWebKeyOperation{
			to.Ptr(azkeys.JSONWebKeyOperationSign),
			to.Ptr(azkeys.JSONWebKeyOperationVerify),
		},
	}

	pk, err := crypto.GenerateKey()
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	// Derive the public key from the private key
	pubKey := pk.Public().(*ecdsa.PublicKey)

	// Generate the Ethereum address from the public key
	keyname := crypto.PubkeyToAddress(*pubKey).Hex()

	createKeyResponse, err := w.KeyClient.CreateKey(ctx, strings.TrimPrefix(keyname, "0x"), keyParams, nil)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	var publicKey []byte
	publicKey = append(publicKey, createKeyResponse.Key.X...)
	publicKey = append(publicKey, createKeyResponse.Key.Y...)
	if len(publicKey) != 64 {
		return ethtypes.Address0xHex{}, errors.New("invalid public key length")
	}

	hash := crypto.Keccak256(publicKey)
	address := common.BytesToAddress(hash[12:])

	tags := map[string]*string{
		"EthereumAddress": to.Ptr(address.Hex()),
	}
	_, err = w.KeyClient.UpdateKey(ctx, strings.TrimPrefix(keyname, "0x"), createKeyResponse.Key.KID.Version(), azkeys.UpdateKeyParameters{
		Tags: tags,
	}, nil)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	return ethtypes.Address0xHex(address), nil
}

func (w *azWallet) ImportKey(ctx context.Context, privateKeyHex string) (ethtypes.Address0xHex, error) {
	privateKey, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}
	keypair, err := secp256k1.NewSecp256k1KeyPair(privateKey)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	// Import the key into Azure Key Vault
	jsonWebKey := azkeys.JSONWebKey{
		Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
		Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP256K),
		X:   keypair.PublicKeyBytes()[0:32],
		Y:   keypair.PublicKeyBytes()[32:64],
		D:   keypair.PrivateKeyBytes(),
		KeyOps: []*string{
			to.Ptr(string(azkeys.JSONWebKeyOperationSign)),
			to.Ptr(string(azkeys.JSONWebKeyOperationVerify)),
		},
	}

	importKeyParams := azkeys.ImportKeyParameters{
		HSM:           to.Ptr(false),
		Key:           &jsonWebKey,
		KeyAttributes: &azkeys.KeyAttributes{Enabled: to.Ptr(true)},
		Tags: map[string]*string{
			"EthereumAddress": to.Ptr(keypair.Address.String()),
		},
	}

	var importKeyResponse azkeys.ImportKeyResponse
	importKeyResponse, err = w.KeyClient.ImportKey(ctx, strings.TrimPrefix(keypair.Address.String(), "0x"), importKeyParams, nil)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	var publicKey []byte
	publicKey = append(publicKey, importKeyResponse.Key.X...)
	publicKey = append(publicKey, importKeyResponse.Key.Y...)
	if len(publicKey) != 64 {
		return ethtypes.Address0xHex{}, errors.New("invalid public key length")
	}

	hash := crypto.Keccak256(publicKey)
	address := common.BytesToAddress(hash[12:])

	if ethtypes.Address0xHex(address) != keypair.Address {
		return ethtypes.Address0xHex{}, errors.New("Fail generate public key")
	}

	return ethtypes.Address0xHex(address), nil
}