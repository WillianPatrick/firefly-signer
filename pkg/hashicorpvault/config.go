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
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
)

var (
	VaultAddress                     = config.AddRootKey("vaultAddress")
	Token                            = config.AddRootKey("token")
	RemoteSign                       = config.AddRootKey("remoteSign")
	SecretsPath                      = config.AddRootKey("secretsPath")
	TransitPath                      = config.AddRootKey("transitPath")
	CacheMaxSize                     = config.AddRootKey("cache.maxSize")
	CacheItemsToPrune                = config.AddRootKey("cache.itemsToPrune")
	CacheTTL                         = config.AddRootKey("cache.ttl")
	MappingKeyAddressEnabled         = config.AddRootKey("mappingKeyAddress.enabled")
	MappingKeyAddressRefreshEnabled  = config.AddRootKey("mappingKeyAddress.refresh.enabled")
	MappingKeyAddressRefreshInterval = config.AddRootKey("mappingKeyAddress.refresh.interval")
)

func InitConfig(section config.Section) {
	section.AddKnownKey(string(VaultAddress))
	section.AddKnownKey(string(Token))
	section.AddKnownKey(string(RemoteSign))
	section.AddKnownKey(string(SecretsPath))
	section.AddKnownKey(string(TransitPath))
	section.AddKnownKey(string(CacheMaxSize))
	section.AddKnownKey(string(CacheItemsToPrune))
	section.AddKnownKey(string(CacheTTL))
	section.AddKnownKey(string(MappingKeyAddressEnabled))
	section.AddKnownKey(string(MappingKeyAddressRefreshEnabled))
	section.AddKnownKey(string(MappingKeyAddressRefreshInterval))
}

func ReadConfig(section config.Section) *Config {
	return &Config{
		VaultAddress: section.GetString(string(VaultAddress)),
		Token:        section.GetString(string(Token)),
		RemoteSign:   section.GetBool(string(RemoteSign)),
		SecretsPath:  section.GetString(string(SecretsPath)),
		TransitPath:  section.GetString(string(TransitPath)),
		Cache: ConfigCache{
			MaxSize:      section.GetInt64(string(CacheMaxSize)),
			ItemsToPrune: uint32(section.GetInt(string(CacheItemsToPrune))),
			TTL:          section.GetDuration(string(CacheTTL)),
		},
		MappingKeyAddress: MappingKeyAddress{
			Enabled: section.GetBool(string(MappingKeyAddressEnabled)),
			Refresh: MappingKeyAddressRefresh{
				Enabled:  section.GetBool(string(MappingKeyAddressRefreshEnabled)),
				Interval: section.GetDuration(string(MappingKeyAddressRefreshInterval)),
			},
		},
	}
}

type MappingKeyAddressRefresh struct {
	Enabled  bool
	Interval time.Duration
}

type MappingKeyAddress struct {
	Enabled bool
	Refresh MappingKeyAddressRefresh
}

type ConfigCache struct {
	MaxSize      int64
	ItemsToPrune uint32
	TTL          time.Duration
}

type Config struct {
	VaultAddress      string
	Token             string
	RemoteSign        bool
	SecretsPath       string
	TransitPath       string
	Cache             ConfigCache
	MappingKeyAddress MappingKeyAddress
}
