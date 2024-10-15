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
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
)

var securitySection config.Section

// Configuration keys for AWS KMS
var (
	ConfigSecurityPrivateAddresKey                      = config.AddRootKey("anonymizedAddressKey")
	ConfigEnabled                                       = config.AddRootKey("enabled")
	ConfigRegion                                        = config.AddRootKey("region")
	ConfigAccessKeyID                                   = config.AddRootKey("accessKeyID")
	ConfigSecretAccessKey                               = config.AddRootKey("secretAccessKey")
	ConfigSecretsEnabled                                = config.AddRootKey("secrets.enabled")
	ConfigSecretsCacheEnabled                           = config.AddRootKey("secrets.cache.enabled")
	ConfigSecretsCacheMaxSize                           = config.AddRootKey("secrets.cache.maxSize")
	ConfigSecretsCacheItemsToPrune                      = config.AddRootKey("secrets.cache.itemsToPrune")
	ConfigSecretsCacheTTL                               = config.AddRootKey("secrets.cache.ttl")
	ConfigKMSEnabled                                    = config.AddRootKey("kms.enabled")
	ConfigKMSMemoryMappingAddressKeyNameRefreshEnabled  = config.AddRootKey("kms.memoryMappingAddressKeyName.refresh.enabled")
	ConfigKMSMemoryMappingAddressKeyNameRefreshInterval = config.AddRootKey("kms.memoryMappingAddressKeyName.refresh.interval")
)

// InitConfig initializes known configuration keys for AWS KMS.
func InitConfig(section config.Section, security config.Section) {

	securitySection = security
	securitySection.AddKnownKey(string(ConfigSecurityPrivateAddresKey))

	section.AddKnownKey(string(ConfigEnabled))
	section.AddKnownKey(string(ConfigRegion))
	section.AddKnownKey(string(ConfigAccessKeyID))
	section.AddKnownKey(string(ConfigSecretAccessKey))
	section.AddKnownKey(string(ConfigSecretsEnabled), true)
	section.AddKnownKey(string(ConfigSecretsCacheEnabled), true)
	section.AddKnownKey(string(ConfigSecretsCacheMaxSize), int64(1000))
	section.AddKnownKey(string(ConfigSecretsCacheItemsToPrune), uint32(100))
	section.AddKnownKey(string(ConfigSecretsCacheTTL), 1*time.Hour)
	section.AddKnownKey(string(ConfigKMSEnabled), true)
	section.AddKnownKey(string(ConfigKMSMemoryMappingAddressKeyNameRefreshEnabled), true)
	section.AddKnownKey(string(ConfigKMSMemoryMappingAddressKeyNameRefreshInterval), 5*time.Minute)
}

// ReadConfig reads and parses the AWS KMS configuration from the provided section.
func ReadConfig(section config.Section) *Config {
	return &Config{
		Region:            section.GetString(string(ConfigRegion)),
		PrivateAddressKey: securitySection.GetString(string(ConfigSecurityPrivateAddresKey)),
		AccessKeyID:       section.GetString(string(ConfigAccessKeyID)),
		SecretAccessKey:   section.GetString(string(ConfigSecretAccessKey)),
		Secrets: Secrets{
			Enabled: section.GetBool(string(ConfigSecretsEnabled)),
			Cache: SecretsCache{
				Enabled:      section.GetBool(string(ConfigSecretsCacheEnabled)),
				MaxSize:      section.GetInt64(string(ConfigSecretsCacheMaxSize)),
				ItemsToPrune: uint32(section.GetInt(string(ConfigSecretsCacheItemsToPrune))),
				TTL:          section.GetDuration(string(ConfigSecretsCacheTTL)),
			},
		},
		KMS: KMS{
			Enabled: section.GetBool(string(ConfigKMSEnabled)),
			MappingAddressKeyNameRefresh: KMSMappingAddressKeyNameRefresh{
				Enabled:  section.GetBool(string(ConfigKMSMemoryMappingAddressKeyNameRefreshEnabled)),
				Interval: section.GetDuration(string(ConfigKMSMemoryMappingAddressKeyNameRefreshInterval)),
			},
		},
	}
}

// Config holds the complete configuration for AWS KMS.
type Config struct {
	Region            string  // AWS region where KMS keys are located
	AccessKeyID       string  // AWS Access Key ID for authentication
	SecretAccessKey   string  // AWS Secret Access Key for authentication
	Secrets           Secrets // Enable or disable AWS Secrets Manager usage
	KMS               KMS     // Enable or disable AWS KMS usage
	PrivateAddressKey string  // Global secret key for encryption/decryption
}

type Secrets struct {
	Enabled bool
	Cache   SecretsCache
}

type KMS struct {
	Enabled                      bool
	MappingAddressKeyNameRefresh KMSMappingAddressKeyNameRefresh
}

// MappingKeyAddressRefresh holds the refresh settings for key-address mapping.
type KMSMappingAddressKeyNameRefresh struct {
	Enabled  bool          // Enable automatic refreshing of the mapping
	Interval time.Duration // Interval duration for refreshing the mapping
}

// ConfigCache holds the cache configuration settings.
type SecretsCache struct {
	Enabled      bool
	MaxSize      int64
	ItemsToPrune uint32
	TTL          time.Duration
}
