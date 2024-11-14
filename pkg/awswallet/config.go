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
	"github.com/hyperledger/firefly-common/pkg/config"
)

// Configuration keys for AWS KMS
var (
	ConfigSecurityPrivateAddresKey = config.AddRootKey("anonymizedAddressKey")
	ConfigMongoDBConnectionString  = config.AddRootKey("connectionString")
	ConfigMongoDBDatabaseName      = config.AddRootKey("databaseName")
	ConfigMongoDBCollectionName    = config.AddRootKey("collectionName")
	ConfigEnabled                  = config.AddRootKey("enabled")
	ConfigRegion                   = config.AddRootKey("region")
	ConfigAccessKeyID              = config.AddRootKey("accessKeyID")
	ConfigSecretAccessKey          = config.AddRootKey("secretAccessKey")
	ConfigUseSecrets               = config.AddRootKey("useSecrets")
	ConfigUseKMS                   = config.AddRootKey("useKMS")
	ConfigEncryptSecrets           = config.AddRootKey("encryptSecrets")
)

// Config holds the complete configuration for AWS KMS.
type Config struct {
	Region            string
	AccessKeyID       string
	SecretAccessKey   string
	UseSecrets        bool
	UseKMS            bool
	EncryptSecrets    bool
	PrivateAddressKey string
	MongoDB           MongoDBConfig
}

type MongoDBConfig struct {
	ConnectionString string
	DatabaseName     string
	CollectionName   string
}

// InitConfig initializes known configuration keys for AWS KMS.
func InitConfig(walletSection config.Section, securitySection config.Section, walletDBSection config.Section) {

	securitySection.AddKnownKey(string(ConfigSecurityPrivateAddresKey))

	walletDBSection.AddKnownKey(string(ConfigMongoDBConnectionString))
	walletDBSection.AddKnownKey(string(ConfigMongoDBDatabaseName))
	walletDBSection.AddKnownKey(string(ConfigMongoDBCollectionName))

	walletSection.AddKnownKey(string(ConfigEnabled))
	walletSection.AddKnownKey(string(ConfigRegion))
	walletSection.AddKnownKey(string(ConfigAccessKeyID))
	walletSection.AddKnownKey(string(ConfigSecretAccessKey))
	walletSection.AddKnownKey(string(ConfigUseSecrets), true)
	walletSection.AddKnownKey(string(ConfigUseKMS), true)
	walletSection.AddKnownKey(string(ConfigEncryptSecrets), true)
}

// ReadConfig reads and parses the AWS KMS configuration from the provided section.
func ReadConfig(walletSection config.Section, securitySection config.Section, walletDBSection config.Section) *Config {
	return &Config{
		Region:            walletSection.GetString(string(ConfigRegion)),
		PrivateAddressKey: securitySection.GetString(string(ConfigSecurityPrivateAddresKey)),
		AccessKeyID:       walletSection.GetString(string(ConfigAccessKeyID)),
		SecretAccessKey:   walletSection.GetString(string(ConfigSecretAccessKey)),
		UseSecrets:        walletSection.GetBool(string(ConfigUseSecrets)),
		UseKMS:            walletSection.GetBool(string(ConfigUseKMS)),
		EncryptSecrets:    walletSection.GetBool(string(ConfigEncryptSecrets)),
		MongoDB: MongoDBConfig{
			ConnectionString: walletDBSection.GetString(string(ConfigMongoDBConnectionString)),
			DatabaseName:     walletDBSection.GetString(string(ConfigMongoDBDatabaseName)),
			CollectionName:   walletDBSection.GetString(string(ConfigMongoDBCollectionName)),
		},
	}
}
