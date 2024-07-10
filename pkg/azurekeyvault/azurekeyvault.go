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
	"encoding/json"
	"time"

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

func NewAzureKeyVaultClient(vaultURL, clientID, clientSecret, tenantID string, cache map[string]interface{}) (*AzureKeyVaultClient, error) {
	cred, err := azidentity.NewClientSecretCredential(tenantID, clientID, clientSecret, nil)
	if err != nil {
		return nil, err
	}

	client, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return nil, err
	}

	maxSize := cache["maxSize"].(int64)
	itemsToPrune := cache["itemsToPrune"].(uint32)
	ttl := cache["ttl"].(time.Duration)

	_cache := ccache.New(ccache.Configure().MaxSize(maxSize).ItemsToPrune(itemsToPrune))

	return &AzureKeyVaultClient{Client: client, KeyName: "", Cache: _cache, CacheTTL: ttl}, nil
}

func (c *AzureKeyVaultClient) Initialize(ctx context.Context) error {
	return nil // No initialization needed for Azure Key Vault
}

func (c *AzureKeyVaultClient) Sign(ctx context.Context, txn *ethsigner.Transaction, chainID int64) ([]byte, error) {
	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
	item := c.Cache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		secretResp, err := c.Client.GetSecret(ctx, c.KeyName, "", nil) // Pass empty string for keyVersion
		if err != nil {
			return nil, err
		}

		privateKey = *secretResp.Value
		c.Cache.Set(key, privateKey, c.CacheTTL)
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	return txn.Sign(keypair, chainID)
}

func (c *AzureKeyVaultClient) SignTypedDataV4(ctx context.Context, from ethtypes.Address0xHex, payload *eip712.TypedData) (*ethsigner.EIP712Result, error) {
	key := from.String()
	item := c.Cache.Get(key)
	var privateKey string

	if item != nil && !item.Expired() {
		privateKey = item.Value().(string)
	} else {
		secretResp, err := c.Client.GetSecret(ctx, c.KeyName, "", nil) // Pass empty string for keyVersion
		if err != nil {
			return nil, err
		}

		privateKey = *secretResp.Value
		c.Cache.Set(key, privateKey, c.CacheTTL)
	}

	keypair, err := secp256k1.NewSecp256k1KeyPair([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	return ethsigner.SignTypedDataV4(ctx, keypair, payload)
}

func (c *AzureKeyVaultClient) GetAccounts(ctx context.Context) ([]*ethtypes.Address0xHex, error) {
	// Implementar a lógica para retornar a lista de contas
	return []*ethtypes.Address0xHex{}, nil
}

func (c *AzureKeyVaultClient) Refresh(ctx context.Context) error {
	// Implementar a lógica para atualizar os dados conforme necessário
	return nil
}

func (c *AzureKeyVaultClient) Close() error {
	// Cleanup resources if necessary
	return nil
}
