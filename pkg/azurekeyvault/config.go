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

import "github.com/hyperledger/firefly-common/pkg/config"

var (
	VaultURL          = config.AddRootKey("vaultURL")
	ClientID          = config.AddRootKey("clientID")
	ClientSecret      = config.AddRootKey("clientSecret")
	TenantID          = config.AddRootKey("tenantID")
	CacheMaxSize      = config.AddRootKey("cache.maxSize")
	CacheItemsToPrune = config.AddRootKey("cache.itemsToPrune")
	CacheTTL          = config.AddRootKey("cache.ttl")
)

func InitConfig(section config.Section) {
	section.AddKnownKey(string(VaultURL))
	section.AddKnownKey(string(ClientID))
	section.AddKnownKey(string(ClientSecret))
	section.AddKnownKey(string(TenantID))
	section.AddKnownKey(string(CacheMaxSize))
	section.AddKnownKey(string(CacheItemsToPrune))
	section.AddKnownKey(string(CacheTTL))
}

func ReadConfig(section config.Section) *Config {
	return &Config{
		VaultURL:     section.GetString(string(VaultURL)),
		ClientID:     section.GetString(string(ClientID)),
		ClientSecret: section.GetString(string(ClientSecret)),
		TenantID:     section.GetString(string(TenantID)),
		Cache: map[string]interface{}{
			"maxSize":      section.GetInt64(string(CacheMaxSize)),
			"itemsToPrune": uint32(section.GetInt(string(CacheItemsToPrune))),
			"ttl":          section.GetDuration(string(CacheTTL)),
		},
	}
}
