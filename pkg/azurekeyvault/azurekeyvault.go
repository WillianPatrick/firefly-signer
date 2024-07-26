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
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/keyvault/azsecrets"
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
	var from ethtypes.Address0xHex
	if err := json.Unmarshal(txn.From, &from); err != nil {
		return nil, err
	}
	key := from.String()
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
	}

	w.signerCache.Set(key, privateKey, w.signerCacheTTL)

	keypair, err := secp256k1.NewSecp256k1KeyPair([]byte(privateKey))
	if err != nil {
		return nil, err
	}

	txn.Nonce = ethtypes.NewHexInteger64(txn.Nonce.Int64() - 1)
	return txn.Sign(keypair, chainID)
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
