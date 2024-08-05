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
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
)

var (
	VaultURL          = config.AddRootKey("vaultURL")
	ClientID          = config.AddRootKey("clientID")
	ClientSecret      = config.AddRootKey("clientSecret")
	TenantID          = config.AddRootKey("tenantID")
	RemoteSign        = config.AddRootKey("remoteSign")
	CacheMaxSize      = config.AddRootKey("cache.maxSize")
	CacheItemsToPrune = config.AddRootKey("cache.itemsToPrune")
	CacheTTL          = config.AddRootKey("cache.ttl")
	RefreshInterval   = config.AddRootKey("refreshInterval")
	EnableRefresh     = config.AddRootKey("enableRefresh")
)

func InitConfig(section config.Section) {
	section.AddKnownKey(string(VaultURL))
	section.AddKnownKey(string(ClientID))
	section.AddKnownKey(string(ClientSecret))
	section.AddKnownKey(string(TenantID))
	section.AddKnownKey(string(CacheMaxSize))
	section.AddKnownKey(string(CacheItemsToPrune))
	section.AddKnownKey(string(CacheTTL))
	section.AddKnownKey(string(RemoteSign))
	section.AddKnownKey(string(RefreshInterval))
	section.AddKnownKey(string(EnableRefresh))
}

func ReadConfig(section config.Section) *Config {
	return &Config{
		VaultURL:     section.GetString(string(VaultURL)),
		ClientID:     section.GetString(string(ClientID)),
		ClientSecret: section.GetString(string(ClientSecret)),
		TenantID:     section.GetString(string(TenantID)),
		RemoteSign:   section.GetBool(string(RemoteSign)),

		Cache: ConfigCache{
			MaxSize:      section.GetInt64(string(CacheMaxSize)),
			ItemsToPrune: uint32(section.GetInt(string(CacheItemsToPrune))),
			TTL:          section.GetDuration(string(CacheTTL)),
		},

		RefreshInterval: section.GetDuration(string(RefreshInterval)),
		EnableRefresh:   section.GetBool(string(EnableRefresh)),
	}
}

type ConfigCache struct {
	MaxSize      int64
	ItemsToPrune uint32
	TTL          time.Duration
}

type Config struct {
	VaultURL        string
	ClientID        string
	ClientSecret    string
	TenantID        string
	RemoteSign      bool
	Cache           ConfigCache
	RefreshInterval time.Duration
	EnableRefresh   bool
}
