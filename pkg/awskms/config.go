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

package awskms

import (
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
)

// Configuration keys for AWS KMS
var (
	Region                           = config.AddRootKey("region")
	RemoteSign                       = config.AddRootKey("remoteSign")
	AccessKeyID                      = config.AddRootKey("accessKeyID")
	SecretAccessKey                  = config.AddRootKey("secretAccessKey")
	MappingKeyAddressEnabled         = config.AddRootKey("mappingKeyAddress.enabled")
	MappingKeyAddressRefreshEnabled  = config.AddRootKey("mappingKeyAddress.refresh.enabled")
	MappingKeyAddressRefreshInterval = config.AddRootKey("mappingKeyAddress.refresh.interval")
)

// InitConfig initializes known configuration keys for AWS KMS.
func InitConfig(section config.Section) {
	section.AddKnownKey(string(Region))
	section.AddKnownKey(string(AccessKeyID))
	section.AddKnownKey(string(SecretAccessKey))
	section.AddKnownKey(string(RemoteSign))
	section.AddKnownKey(string(MappingKeyAddressEnabled))
	section.AddKnownKey(string(MappingKeyAddressRefreshEnabled))
	section.AddKnownKey(string(MappingKeyAddressRefreshInterval))
}

// ReadConfig reads and parses the AWS KMS configuration from the provided section.
func ReadConfig(section config.Section) *Config {
	return &Config{
		Region:          section.GetString(string(Region)),
		RemoteSign:      section.GetBool(string(RemoteSign)),
		AccessKeyID:     section.GetString(string(AccessKeyID)),
		SecretAccessKey: section.GetString(string(SecretAccessKey)),
		MappingKeyAddress: MappingKeyAddress{
			Enabled: section.GetBool(string(MappingKeyAddressEnabled)),
			Refresh: MappingKeyAddressRefresh{
				Enabled:  section.GetBool(string(MappingKeyAddressRefreshEnabled)),
				Interval: section.GetDuration(string(MappingKeyAddressRefreshInterval)),
			},
		},
	}
}

// MappingKeyAddressRefresh holds the refresh settings for key-address mapping.
type MappingKeyAddressRefresh struct {
	Enabled  bool          // Enable automatic refreshing of the mapping
	Interval time.Duration // Interval duration for refreshing the mapping
}

// MappingKeyAddress holds the settings for mapping Ethereum addresses to AWS KMS Key IDs.
type MappingKeyAddress struct {
	Enabled bool                     // Enable or disable the key-address mapping feature
	Refresh MappingKeyAddressRefresh // Refresh settings for the key-address mapping
}

// Config holds the complete configuration for AWS KMS.
type Config struct {
	Region            string            // AWS region where KMS keys are located
	RemoteSign        bool              // Enable or disable remote signing via AWS KMS
	AccessKeyID       string            // AWS Access Key ID for authentication
	SecretAccessKey   string            // AWS Secret Access Key for authentication
	MappingKeyAddress MappingKeyAddress // Mapping configuration settings between addresses and Key IDs
}
