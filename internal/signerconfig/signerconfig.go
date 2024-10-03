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
	"github.com/hyperledger/firefly-signer/pkg/awskms"
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
	AWSKMSEnabled                     = ffc("awsKMS.enabled")
	AWSKMSMappingKeysEnabled          = ffc("awsKMS.mappingKeyAddress.enabled")
	AWSKMSMappingKeysRefreshEnabled   = ffc("awsKMS.mappingKeyAddress.refresh.enabled")
)

// Configuration sections
var (
	ServerConfig     config.Section
	CorsConfig       config.Section
	BackendConfig    config.Section
	FileWalletConfig config.Section
	KeyVaultConfig   config.Section
	AWSKMSConfig     config.Section
)

func setDefaults() {
	viper.SetDefault(string(BackendChainID), -1)
	viper.SetDefault(string(FileWalletEnabled), true)
	viper.SetDefault(string(KeyVaultEnabled), false)
	viper.SetDefault(string(KeyVaultMappingKeysEnabled), false)
	viper.SetDefault(string(KeyVaultMappingKeysRefreshEnabled), false)
	viper.SetDefault(string(AWSKMSEnabled), false)
	viper.SetDefault(string(AWSKMSMappingKeysEnabled), false)
	viper.SetDefault(string(AWSKMSMappingKeysRefreshEnabled), false)
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

	AWSKMSConfig = config.RootSection("awsKMS")
	awskms.InitConfig(AWSKMSConfig)
}
