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

package hashicorpvault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	vault "github.com/hashicorp/vault/api"
	"github.com/hyperledger/firefly-common/pkg/log"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/karlseguin/ccache"
)

const keyPath = "/keys/"

type Wallet interface {
	ethsigner.WalletTypedData
	CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error)
	AddMappingKeyAddress(address string, data []byte) error
	Initialize(ctx context.Context) error
	Close() error
}

type vaultWallet struct {
	conf             Config
	signerCache      *ccache.Cache
	signerCacheTTL   time.Duration
	vaultClient      *vault.Client
	stopRefresh      chan struct{}
	addressToKeyName map[common.Address]string
}

func NewVaultWallet(ctx context.Context, conf *Config) (Wallet, error) {
	w := &vaultWallet{
		conf: *conf,
	}

	vaultConfig := vault.DefaultConfig()
	vaultConfig.Address = conf.VaultAddress

	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	if conf.Token != "" {
		client.SetToken(conf.Token)
	}

	w.vaultClient = client

	maxSize := conf.Cache.MaxSize
	if maxSize == 0 {
		maxSize = int64(100)
	}
	itemsToPrune := conf.Cache.ItemsToPrune
	if itemsToPrune == 0 {
		itemsToPrune = uint32(10)
	}

	w.signerCache = ccache.New(ccache.Configure().MaxSize(maxSize).ItemsToPrune(itemsToPrune))
	w.signerCacheTTL = conf.Cache.TTL

	w.addressToKeyName = make(map[common.Address]string)

	return w, nil
}

func (w *vaultWallet) Initialize(ctx context.Context) error {
	if w.conf.MappingKeyAddress.Enabled && w.conf.MappingKeyAddress.Refresh.Enabled {
		w.startRefreshLoop(ctx)
	}
	return nil
}

func (w *vaultWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	if !w.conf.RemoteSign {
		return w.LocalSign(ctx, txn, chainID)
	}
	return w.RemoteSign(ctx, txn, chainID)
}

func (w *vaultWallet) LocalSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxBytes, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("Vault - Local Sign - Chain ID: %d - From: %s, Unsigned transaction txn: %s", chainID, key, string(unsignedTxBytes))

	item := w.signerCache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		secretPath := w.conf.SecretsPath + "/" + strings.TrimPrefix(key, "0x")
		secret, err := w.vaultClient.Logical().Read(secretPath)
		if err != nil {
			return nil, err
		}
		if secret == nil || secret.Data == nil {
			return nil, errors.New("chave privada não encontrada no Vault")
		}
		privateKey = secret.Data["privateKey"].(string)
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

	log.L(ctx).Debugf("Vault - Local Sign - Chain ID: %d - From: %s, Signed transaction: %s", chainID, key, hex.EncodeToString(signedTx))

	return signedTx, nil
}

func (w *vaultWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	unsignedTxnJSON, err := json.Marshal(txn)
	if err != nil {
		return nil, err
	}

	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	log.L(ctx).Debugf("Vault - Remote Sign - Chain ID: %d - From: %s, Unsigned transaction txn: %s", chainID, key, string(unsignedTxnJSON))

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

	keyName, err := w.getKeyNameForAddress(from)
	if err != nil {
		return nil, err
	}

	signPath := w.conf.TransitPath + "/sign/" + keyName

	data := map[string]interface{}{
		"input":               hex.EncodeToString(hash[:]),
		"prehashed":           true,
		"signature_algorithm": "ecdsa-p256k1-sha256",
	}

	secret, err := w.vaultClient.Logical().Write(signPath, data)
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, errors.New("falha ao obter a assinatura do Vault")
	}

	signatureHex := secret.Data["signature"].(string)
	signatureBytes, err := hex.DecodeString(strings.TrimPrefix(signatureHex, "vault:v1:"))
	if err != nil {
		return nil, err
	}

	r, s, err := parseDERSignature(signatureBytes)
	if err != nil {
		return nil, err
	}

	// Certifique-se de que 's' está na metade inferior
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

	var signature = append(rPadded, sPadded...)

	// Recuperar o ID de recuperação (v)
	publicKey, err := w.getPublicKeyForKeyName(keyName)
	if err != nil {
		return nil, err
	}

	recID := -1
	for i := 0; i < 2; i++ {
		v := byte(i + 27)
		var sig = append(signature, v)
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
		return nil, errors.New("falha ao recuperar a chave pública")
	}

	v := byte(recID + 27 + int(chainID)*2)

	var sig = append(signature, v)

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
	var sig struct{ R, S *big.Int }
	_, err = asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, nil, err
	}
	return sig.R, sig.S, nil
}

func (w *vaultWallet) getKeyNameForAddress(address ethtypes.Address0xHex) (string, error) {
	if keyName, exists := w.addressToKeyName[common.Address(address)]; exists {
		return keyName, nil
	}
	return "", errors.New("key Name não encontrado para o endereço")
}

func (w *vaultWallet) getPublicKeyForKeyName(keyName string) (*ecdsa.PublicKey, error) {
	readPath := w.conf.TransitPath + keyPath + keyName

	secret, err := w.vaultClient.Logical().Read(readPath)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New("falha ao obter a chave pública do Vault")
	}

	keysData := secret.Data["keys"].(map[string]interface{})
	latestVersion := secret.Data["latest_version"].(json.Number).String()

	keyInfo := keysData[latestVersion].(map[string]interface{})
	publicKeyPem := keyInfo["public_key"].(string)

	publicKeyBytes, _ := pemDecode(publicKeyPem)
	pubKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pubKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("a chave pública não é ECDSA")
	}
	return pubKey, nil
}

func pemDecode(pemStr string) ([]byte, string) {
	block, rest := pemDecodeBlock([]byte(pemStr))
	if block == nil {
		return nil, ""
	}
	return block.Bytes, string(rest)
}

func pemDecodeBlock(data []byte) (*pem.Block, []byte) {
	for {
		block, rest := pem.Decode(data)
		if block == nil {
			return nil, rest
		}
		if block.Type != "" {
			return block, rest
		}
		data = rest
	}
}

func (w *vaultWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
	if !w.conf.RemoteSign {
		address, err := w.CreateSecret(ctx, password, privateKeyHex)
		if err != nil {
			return ethsigner.CreateWalletResponse{}, err
		}
		return ethsigner.CreateWalletResponse{
			Address: strings.TrimPrefix(address.String(), "0x"),
		}, nil
	}
	return w.CreateKey(ctx, privateKeyHex)
}

func (w *vaultWallet) CreateSecret(ctx context.Context, password string, privateKeyHex string) (ethtypes.Address0xHex, error) {
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
	err = w.storeKeyPairInVault(keypair)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}
	return keypair.Address, nil
}

func (w *vaultWallet) storeKeyPairInVault(keypair *secp256k1.KeyPair) error {
	secretPath := w.conf.SecretsPath + "/" + strings.TrimPrefix(keypair.Address.String(), "0x")
	data := map[string]interface{}{
		"privateKey": hex.EncodeToString(keypair.PrivateKeyBytes()),
		"address":    keypair.Address.String(),
	}
	_, err := w.vaultClient.Logical().Write(secretPath, data)
	return err
}

func (w *vaultWallet) CreateKey(ctx context.Context, privateKeyHex string) (ethsigner.CreateWalletResponse, error) {
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

	keyName := generateRandomKeyName()

	createPath := w.conf.TransitPath + keyPath + keyName
	data := map[string]interface{}{
		"type": "ecdsa-p256k1",
	}

	_, err := w.vaultClient.Logical().Write(createPath, data)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, err
	}

	pubKey, err := w.getPublicKeyForKeyName(keyName)
	if err != nil {
		return ethsigner.CreateWalletResponse{}, err
	}

	address := crypto.PubkeyToAddress(*pubKey)
	w.addressToKeyName[address] = keyName

	return ethsigner.CreateWalletResponse{
		Address: strings.TrimPrefix(address.Hex(), "0x"),
		KeyName: keyName,
	}, nil
}

func generateRandomKeyName() string {
	// Implementar uma função para gerar um nome de chave aleatório
	return "key-" + randomString(10)
}

func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func (w *vaultWallet) ImportKey(ctx context.Context, privateKeyHex string) (ethtypes.Address0xHex, string, error) {
	privateKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return ethtypes.Address0xHex{}, "", err
	}

	privateKeyECDSA, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		return ethtypes.Address0xHex{}, "", err
	}

	publicKeyECDSA := privateKeyECDSA.Public().(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	keyName := strings.TrimPrefix(address.Hex(), "0x")

	importPath := w.conf.TransitPath + keyPath + keyName
	data := map[string]interface{}{
		"type":                   "ecdsa-p256k1",
		"allow_plaintext_backup": true,
		"keys": map[string]interface{}{
			"1": map[string]interface{}{
				"private_key": hex.EncodeToString(privateKeyBytes),
			},
		},
	}

	_, err = w.vaultClient.Logical().Write(importPath, data)
	if err != nil {
		return ethtypes.Address0xHex{}, "", err
	}

	w.addressToKeyName[address] = keyName

	return ethtypes.Address0xHex(address), keyName, nil
}

func (w *vaultWallet) AddMappingKeyAddress(address string, data []byte) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return errors.New("recurso de mapeamento não habilitado")
	}
	w.addressToKeyName[common.HexToAddress(address)] = string(data)
	return nil
}

func (w *vaultWallet) Close() error {
	if w.stopRefresh != nil {
		close(w.stopRefresh)
	}
	return nil
}

func (w *vaultWallet) startRefreshLoop(ctx context.Context) {
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
					log.L(ctx).Errorf("falha ao atualizar o mapeamento address-to-keyName: %v", err)
				}
			case <-w.stopRefresh:
				return
			}
		}
	}()
}

func (w *vaultWallet) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	// Implementar se necessário
	return nil, errors.New("signTypedDataV4 não implementado")
}

func (w *vaultWallet) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	accounts := make([]*ethtypes.Address0xHex, 0, len(w.addressToKeyName))
	for address := range w.addressToKeyName {
		addr := ethtypes.Address0xHex(address)
		accounts = append(accounts, &addr)
	}
	return accounts, nil
}

func (w *vaultWallet) Refresh(ctx context.Context) error {
	if !w.conf.MappingKeyAddress.Enabled {
		return nil
	}
	return w.refreshAddressToKeyNameMapping(ctx)
}

func (w *vaultWallet) refreshAddressToKeyNameMapping(ctx context.Context) error {
	log.L(ctx).Debugf("atualizando mapeamento de endereços...")

	listPath := w.conf.TransitPath + "/keys?list=true"
	secret, err := w.vaultClient.Logical().List(listPath)
	if err != nil {
		return err
	}

	if secret == nil || secret.Data == nil {
		return errors.New("falha ao listar chaves do Vault")
	}

	keys := secret.Data["keys"].([]interface{})
	for _, keyInterface := range keys {
		keyName := keyInterface.(string)
		pubKey, err := w.getPublicKeyForKeyName(keyName)
		if err != nil {
			continue
		}
		address := crypto.PubkeyToAddress(*pubKey)
		w.addressToKeyName[address] = keyName
	}

	log.L(ctx).Debugf("atualizado: %d endereços mapeados", len(w.addressToKeyName))

	return nil
}
