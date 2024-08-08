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
	"net/url"
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
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/karlseguin/ccache"
)

type Wallet interface {
	ethsigner.WalletTypedData
	CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) // Add this method
	AddMappingKeyAddress(key string, address string) error
}

func (w *azWallet) Initialize(ctx context.Context) error {
	if w.conf.MappingKeyAddress.Enabled && w.conf.MappingKeyAddress.Refresh.Enabled {
		w.startRefreshLoop(ctx)
	}

	return nil
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

	w.addressToKeyName = make(map[common.Address]string)

	return w, nil
}

type azWallet struct {
	conf             Config
	signerCache      *ccache.Cache
	signerCacheTTL   time.Duration
	mux              sync.Mutex
	Client           *azsecrets.Client
	KeyClient        *azkeys.Client
	stopRefresh      chan struct{}
	addressToKeyName map[common.Address]string
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
	log.L(ctx).Debugf("AzureKeyVault - Local Sign - Chain ID: %d - From: %s, Unsigned transaction tnx: %s", chainID, key, string(unsignedTxBytes))

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

func (w *azWallet) GetAccounts(_ context.Context) ([]*ethtypes.Address0xHex, error) {
	accounts := make([]*ethtypes.Address0xHex, 0, len(w.addressToKeyName))
	for address := range w.addressToKeyName {
		addr := ethtypes.Address0xHex(address)
		accounts = append(accounts, &addr)
	}

	return accounts, nil
}

func (w *azWallet) Refresh(ctx context.Context) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return nil
	}

	return w.refreshAddressToKeyNameMapping(ctx)
}

func (w *azWallet) startRefreshLoop(ctx context.Context) {

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
					log.L(ctx).Errorf("Failed to refresh address-to-keyname mapping: %v", err)
				}
			case <-w.stopRefresh:
				return
			}
		}
	}()
}

func (w *azWallet) Close() error {
	if w.stopRefresh != nil {
		close(w.stopRefresh)
	}
	return nil
}
func (w *azWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if !w.conf.RemoteSign {
		r, _ := w.CreateSecret(ctx, password, privateKeyHex)
		return ethsigner.CreateWalletResponse{
			Address: r.String(),
		}, nil

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

	unsignedTxnJson, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("AzureKeyVault - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction tnx: %s", chainID, key, string(unsignedTxnJson))

	signer := types.NewEIP155Signer(big.NewInt(chainID))
	tx := types.NewTx(&types.LegacyTx{
		Nonce:    txn.Nonce.Uint64(),
		To:       (*common.Address)(txn.To),
		Value:    txn.Value.BigInt(),
		Gas:      txn.GasLimit.Uint64(),
		GasPrice: txn.GasPrice.BigInt(),
		Data:     txn.Data,
	})

	unsignedTxJson, err := json.Marshal(tx)
	if err != nil {
		return nil, err
	}

	hash := signer.Hash(tx)
	signParameters := azkeys.SignParameters{
		Algorithm: to.Ptr(azkeys.JSONWebKeySignatureAlgorithmES256K),
		Value:     hash[:],
	}

	log.L(ctx).Debugf("AzureKeyVault - Remote Sign - Chain ID: %d - From: %s, Send RPC Transaction With Signature: %s", chainID, key, hex.EncodeToString(unsignedTxJson))

	keyname := strings.TrimPrefix(key, "0x")

	if _, exists := w.addressToKeyName[(common.Address)(from)]; exists {
		keyname = strings.TrimPrefix(key, "0x")
	}

	signResult, err := w.KeyClient.Sign(ctx, keyname, "", signParameters, nil)
	if err != nil {
		return nil, err
	}

	signature := signResult.Result
	log.L(ctx).Debugf("AzureKeyVault - Remote Sign - Azure Result Signature (R,S): %s", hex.EncodeToString(signature))

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

	log.L(ctx).Debugf("AzureKeyVault - Remote Sign - Signature (R,S,V): %s", hex.EncodeToString(sig))

	signedTx, err := tx.WithSignature(signer, sig)
	if err != nil {
		return nil, err
	}

	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	signedTxJson, err := json.Marshal(signedTx)
	if err != nil {
		return nil, err
	}

	log.L(ctx).Debugf("AzureKeyVault - Remote Sign - Chain ID: %d - From: %s, Send RPC Transaction With Signature: %s", chainID, key, hex.EncodeToString(signedTxJson))

	return signedTxBytes, nil

}

func (w *azWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if privateKeyHex != "" {
		addr, _ := w.ImportKey(ctx, privateKeyHex)
		return ethsigner.CreateWalletResponse{
			Address: strings.TrimPrefix(addr.String(), "0x"),
			KeyName: addr.String(),
		}, nil
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
		return ethsigner.CreateWalletResponse{}, err
	}

	pubKey := pk.Public().(*ecdsa.PublicKey)
	keyname := crypto.PubkeyToAddress(*pubKey).Hex()

	createKeyResponse, err := w.KeyClient.CreateKey(ctx, strings.TrimPrefix(keyname, "0x"), keyParams, nil)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, err
	}

	var publicKey []byte
	publicKey = append(publicKey, createKeyResponse.Key.X...)
	publicKey = append(publicKey, createKeyResponse.Key.Y...)
	if len(publicKey) != 64 {
		return ethsigner.CreateWalletResponse{}, errors.New("invalid public key length")
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
		return ethsigner.CreateWalletResponse{}, err
	}

	if w.conf.MappingKeyAddress.Enabled {
		w.addressToKeyName[common.HexToAddress(address.Hex())] = strings.TrimPrefix(address.String(), "0x")
	}

	return ethsigner.CreateWalletResponse{
		Address: address.String(),
		KeyName: strings.TrimPrefix(keyname, "0x"),
	}, nil
}

func (w *azWallet) ImportKey(ctx context.Context, privateKeyHex string) (ethtypes.Address0xHex, error) {
	privateKey, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	privateKeyECDSA, err := crypto.ToECDSA(privateKey)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	publicKeyECDSA := privateKeyECDSA.Public().(*ecdsa.PublicKey)
	jsonWebKey := azkeys.JSONWebKey{
		Kty: to.Ptr(azkeys.JSONWebKeyTypeEC),
		Crv: to.Ptr(azkeys.JSONWebKeyCurveNameP256K),
		X:   publicKeyECDSA.X.Bytes(),
		Y:   publicKeyECDSA.Y.Bytes(),
		D:   privateKey,
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
			"EthereumAddress": to.Ptr(crypto.PubkeyToAddress(*publicKeyECDSA).Hex()),
		},
	}

	importKeyResponse, err := w.KeyClient.ImportKey(ctx, strings.TrimPrefix(crypto.PubkeyToAddress(*publicKeyECDSA).Hex(), "0x"), importKeyParams, nil)
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

	if ethtypes.Address0xHex(address) != ethtypes.Address0xHex(crypto.PubkeyToAddress(*publicKeyECDSA).Bytes()) {
		return ethtypes.Address0xHex{}, errors.New("Fail generate public key")
	}

	if w.conf.MappingKeyAddress.Enabled {
		w.addressToKeyName[common.HexToAddress(address.Hex())] = strings.TrimPrefix(address.String(), "0x")
	}

	return ethtypes.Address0xHex(address), nil
}

func (w *azWallet) AddMappingKeyAddress(key string, address string) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return errors.New("mapping feature not enabled")
	}
	w.addressToKeyName[common.HexToAddress(address)] = strings.TrimPrefix(key, "0x")
	return nil
}

func (w *azWallet) refreshAddressToKeyNameMapping(ctx context.Context) error {
	log.L(ctx).Debugf("Updating mapping address...")

	pager := w.KeyClient.NewListKeysPager(nil)

	for pager.More() {
		pageResponse, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}

		for _, keyItem := range pageResponse.Value {
			if keyItem.Tags != nil {
				keyName := extractKeyNameFromKID(keyItem.KID)
				if keyName != "" {
					if _, exists := w.addressToKeyName[(common.Address)(common.HexToAddress("0x"+keyName))]; !exists {
						if addr, ok := keyItem.Tags["EthereumAddress"]; ok {
							ca := common.HexToAddress(*addr)
							if _, exists := w.addressToKeyName[ca]; !exists {
								w.addressToKeyName[ca] = strings.TrimPrefix(keyName, "0x")
							}
						}
					}
				}
			}
		}
	}

	log.L(ctx).Debugf("Updated: %d address to mapping", len(w.addressToKeyName))

	return nil
}

func extractKeyNameFromKID(kid *azkeys.ID) string {
	if kid == nil {
		return ""
	}

	fullURL := string(*kid)
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return ""
	}
	segments := strings.Split(parsedURL.Path, "/")
	if len(segments) >= 3 {
		return segments[2]
	}
	return ""
}
