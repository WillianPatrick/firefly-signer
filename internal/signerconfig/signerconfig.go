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

package signerconfig

import (
	"github.com/hyperledger/firefly-common/pkg/config"
	"github.com/hyperledger/firefly-common/pkg/httpserver"
	"github.com/hyperledger/firefly-common/pkg/wsclient"
	"github.com/hyperledger/firefly-signer/pkg/awswallet"
	"github.com/hyperledger/firefly-signer/pkg/azurekeyvault"
	"github.com/hyperledger/firefly-signer/pkg/fswallet"
	"github.com/spf13/viper"
)

var ffc = config.AddRootKey

// Configuration keys
var (
	BackendChainID                    = ffc("backend.chainId")
	FileWalletEnabled                 = ffc("fileWallet.enabled")
	KeyVaultEnabled                   = ffc("azureKeyVault.enabled")
	KeyVaultMappingKeysEnabled        = ffc("azureKeyVault.mappingKeyAddress.enabled")
	KeyVaultMappingKeysRefreshEnabled = ffc("azureKeyVault.mappingKeyAddress.refresh.enabled")

	// AWS Wallet
	AWSWalletEnabled                                      = ffc("awsWallet.enabled")
	AWSWalletSecretsEnabled                               = ffc("awsWallet.secrets.enabled")
	AWSWalletSecretsCacheEnabled                          = ffc("awsWallet.secrets.cache.enabled")
	AWSWalletKMSEnabled                                   = ffc("awsWallet.kms.enabled")
	AWSWalletKMSMemoryMappingAddressKeyNameRefreshEnabled = ffc("awsWallet.kms.memoryMappingAddressKeyName.refresh.enabled")
)

// Configuration sections
var (
	ServerConfig     config.Section
	Security         config.Section
	CorsConfig       config.Section
	BackendConfig    config.Section
	FileWalletConfig config.Section
	KeyVaultConfig   config.Section
	AWSWalletConfig  config.Section
)

func setDefaults() {
	// Defina valores padrão conforme necessário
	// Descomente para definir um valor padrão temporário
	// viper.SetDefault(string(SecurityAnonymizedAddressKey), "#Firefly-Signer!")
	viper.SetDefault(string(BackendChainID), -1)
	viper.SetDefault(string(FileWalletEnabled), true)
	viper.SetDefault(string(KeyVaultEnabled), false)
	viper.SetDefault(string(KeyVaultMappingKeysEnabled), false)
	viper.SetDefault(string(KeyVaultMappingKeysRefreshEnabled), false)
	viper.SetDefault(string(AWSWalletEnabled), false)
	viper.SetDefault(string(AWSWalletSecretsEnabled), true)
	viper.SetDefault(string(AWSWalletKMSEnabled), true)
	viper.SetDefault(string(AWSWalletKMSMemoryMappingAddressKeyNameRefreshEnabled), false)
}

func Reset() {
	config.RootConfigReset(setDefaults)

	ServerConfig = config.RootSection("server")
	httpserver.InitHTTPConfig(ServerConfig, 8545)

	CorsConfig = config.RootSection("cors")
	httpserver.InitCORSConfig(CorsConfig)

	BackendConfig = config.RootSection("backend")
	wsclient.InitConfig(BackendConfig)

	FileWalletConfig = config.RootSection("fileWallet")
	fswallet.InitConfig(FileWalletConfig)

	KeyVaultConfig = config.RootSection("azureKeyVault")
	azurekeyvault.InitConfig(KeyVaultConfig)

	Security = config.RootSection("security")
	AWSWalletConfig = config.RootSection("awsWallet")
	awswallet.InitConfig(AWSWalletConfig, Security)
}
