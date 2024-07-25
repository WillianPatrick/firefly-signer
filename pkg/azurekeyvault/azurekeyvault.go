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
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
	"github.com/hyperledger/firefly-signer/pkg/eip712"
	"github.com/hyperledger/firefly-signer/pkg/ethsigner"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"github.com/karlseguin/ccache/v2"
)

type AzureKeyVaultClient struct {
	Client   *azsecrets.Client
	KeyName  string
	Cache    *ccache.Cache
	CacheTTL time.Duration
}

type Config struct {
	VaultURL     string
	ClientID     string
	ClientSecret string
	TenantID     string
	Cache        map[string]interface{}
}

type azWallet struct {
	client AzureKeyVaultClient
}

func NewAzureKeyVaultClient(vaultURL, clientID, clientSecret, tenantID string, cache map[string]interface{}) (ethsigner.Wallet, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, err
	}

	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, err
	}

	maxSize := int64(100)
	if ms, ok := cache["maxSize"].(int64); ok {
		maxSize = ms
	}
	itemsToPrune := uint32(10)
	if itp, ok := cache["itemsToPrune"].(uint32); ok {
		itemsToPrune = itp
	}
	ttl := 1 * time.Hour
	if t, ok := cache["ttl"].(time.Duration); ok {
		ttl = t
	}

	_cache := ccache.New(ccache.Configure().MaxSize(maxSize).ItemsToPrune(itemsToPrune))

	azClient := AzureKeyVaultClient{Client: client, KeyName: "", Cache: _cache, CacheTTL: ttl}
	return &azWallet{client: azClient}, nil
}

func (w *azWallet) Initialize(ctx context.Context) error {
	return nil // No initialization needed for Azure Key Vault
}

func (w *azWallet) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	item := w.client.Cache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		secretResp, err := w.client.Client.GetSecret(ctx, w.client.KeyName, "", nil) // Pass empty string for keyVersion
		if err != nil {
			return nil, err
		}

		privateKey = *secretResp.Value
		w.client.Cache.Set(key, privateKey, w.client.CacheTTL)
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	return txn.Sign(keypair, chainID)
}

// func (w *azWallet) RemoteSign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
// 	var from ethtypes.Address0xHex
// 	if err := json.Unmarshal(txn.From, &from); err != nil {
// 		return nil, err
// 	}

// 	// Preparar o payload para assinatura
// 	txHash, err := txn.SigningHash(chainID)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Solicitar a assinatura ao Azure Key Vault
// 	signatureResp, err := w.client.Client.Sign(ctx, w.client.KeyName, azsecrets.SignParameters{
// 		Algorithm: azsecrets.SignatureAlgorithmES256,
// 		Value:     txHash.Bytes(),
// 	}, nil)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Montar a assinatura no formato esperado
// 	signature := signatureResp.Result
// 	r := new(big.Int).SetBytes(signature[:32])
// 	s := new(big.Int).SetBytes(signature[32:64])
// 	v := big.NewInt(int64(chainID*2 + 35))

// 	signedTx, err := txn.MarshalWithSignature(r, s, v)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return signedTx, nil
// }

func (w *azWallet) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	key := from.String()
	item := w.client.Cache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		secretResp, err := w.client.Client.GetSecret(ctx, w.client.KeyName, "", nil) // Pass empty string for keyVersion
		if err != nil {
			return nil, err
		}

		privateKey = *secretResp.Value
		w.client.Cache.Set(key, privateKey, w.client.CacheTTL)
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	return ethsigner.SignTypedDataV4(ctx, keypair, payload)
}

func (w *azWallet) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	return []*ethtypes.Address0xHex{}, nil
}

func (w *azWallet) Refresh(ctx context.Context) error {
	return nil
}

func (w *azWallet) Close() error {
	return nil
}

func (w *azWallet) CreateWallet(ctx context.Context, password string, privateKeyHex string) (ethtypes.Address0xHex, error) {
	var keypair *secp256k1.KeyPair
	var err error

	if privateKeyHex == "" {
		keypair, err = secp256k1.GenerateSecp256k1KeyPair()
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
	} else {
		privateKey, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
		keypair, err = secp256k1.NewSecp256k1KeyPair(privateKey)
		if err != nil {
			return ethtypes.Address0xHex{}, err
		}
	}

	err = w.client.storeKeyPairInAzureKeyVault(ctx, keypair)
	if err != nil {
		return ethtypes.Address0xHex{}, err
	}

	return keypair.Address, nil
}

func (c *AzureKeyVaultClient) storeKeyPairInAzureKeyVault(ctx context.Context, keypair *secp256k1.KeyPair) error {
	secretName := keypair.Address.String()[2:]
	secretValue := hex.EncodeToString(keypair.PrivateKeyBytes())

	parameters := azsecrets.SetSecretParameters{
		Value: to.Ptr(secretValue),
	}

	_, err := c.Client.SetSecret(ctx, secretName, parameters, nil)
	if err != nil {
		return err
	}

	return nil
}
