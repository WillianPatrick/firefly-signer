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

package signermsgs

import (
	"github.com/hyperledger/firefly-common/pkg/i18n"
	"golang.org/x/text/language"
)

var ffc = func(key, translation, fieldType string) i18n.ConfigMessageKey {
	return i18n.FFC(language.AmericanEnglish, key, translation, fieldType)
}

// revive:disable
var (
	ConfigFileWalletEnabled                      = ffc("config.fileWallet.enabled", "Whether the Keystore V3 filesystem wallet is enabled", "boolean")
	ConfigFileWalletPath                         = ffc("config.fileWallet.path", "Path on the filesystem where the metadata files (and/or key files) are located", "string")
	ConfigFileWalletFilenamesPrimaryBatchRegex   = ffc("config.fileWallet.filenames.primaryMatchRegex", "Regular expression run against key/metadata filenames to extract the address (takes precedence over primaryExt)", "regexp")
	ConfigFileWalletFilenamesWith0xPrefix        = ffc("config.fileWallet.filenames.with0xPrefix", "When true and passwordExt is used, password filenames will be generated with an 0x prefix", "boolean")
	ConfigFileWalletFilenamesPrimaryExt          = ffc("config.fileWallet.filenames.primaryExt", "Extension for key/metadata files named by <ADDRESS>.<EXT>", "string")
	ConfigFileWalletFilenamesPasswordExt         = ffc("config.fileWallet.filenames.passwordExt", "Optional to use to look up password files, that sit next to the key files directly. Alternative to metadata when you have a password per keystore", "string")
	ConfigFileWalletFilenamesPasswordPath        = ffc("config.fileWallet.filenames.passwordPath", "Optional directory in which to look for the password files, when passwordExt is configured. Default is the wallet directory", "string")
	ConfigFileWalletFilenamesPasswordTrimSpace   = ffc("config.fileWallet.filenames.passwordTrimSpace", "Whether to trim leading/trailing whitespace (such as a newline) from the password when loaded from file", "boolean")
	ConfigFileWalletDefaultPasswordFile          = ffc("config.fileWallet.defaultPasswordFile", "Optional default password file to use, if one is not specified individually for the key (via metadata, or file extension)", "string")
	ConfigFileWalletDisableListener              = ffc("config.fileWallet.disableListener", "Disable the filesystem listener that automatically detects the creation of new keystore files", "boolean")
	ConfigFileWalletSignerCacheSize              = ffc("config.fileWallet.signerCacheSize", "Maximum of signing keys to hold in memory", "number")
	ConfigFileWalletSignerCacheTTL               = ffc("config.fileWallet.signerCacheTTL", "How long to leave an unused signing key in memory", "duration")
	ConfigFileWalletMetadataFormat               = ffc("config.fileWallet.metadata.format", "Set this if the primary key file is a metadata file. Supported formats: auto (from extension) / filename / toml / yaml / json (please quote \"0x...\" strings in YAML)", "string")
	ConfigFileWalletMetadataKeyFileProperty      = ffc("config.fileWallet.metadata.keyFileProperty", "Go template to look up the key-file path from the metadata. Example: '{{ index .signing \"key-file\" }}'", "go-template")
	ConfigFileWalletMetadataPasswordFileProperty = ffc("config.fileWallet.metadata.passwordFileProperty", "Go template to look up the password-file path from the metadata", "go-template")

	ConfigServerAddress      = ffc("config.server.address", "Local address for the JSON/RPC server to listen on", "string")
	ConfigServerPort         = ffc("config.server.port", "Port for the JSON/RPC server to listen on", "number")
	ConfigAPIPublicURL       = ffc("config.server.publicURL", "External address callers should access API over", "string")
	ConfigServerReadTimeout  = ffc("config.server.readTimeout", "The maximum time to wait when reading from an HTTP connection", "duration")
	ConfigServerWriteTimeout = ffc("config.server.writeTimeout", "The maximum time to wait when writing to a HTTP connection", "duration")
	ConfigAPIShutdownTimeout = ffc("config.server.shutdownTimeout", "The maximum amount of time to wait for any open HTTP requests to finish before shutting down the HTTP server", i18n.TimeDurationType)

	ConfigBackendChainID  = ffc("config.backend.chainId", "Optionally set the Chain ID of the blockchain. Otherwise the Network ID will be queried, and used as the Chain ID in signing", "number")
	ConfigBackendURL      = ffc("config.backend.url", "URL for the backend JSON/RPC server / blockchain node", "url")
	ConfigBackendProxyURL = ffc("config.backend.proxy.url", "Optional HTTP proxy URL", "url")

	SecurityPrivateAddressKey = ffc("config.security.anonymizedAddressKey", "The Privacity Local Key for encryption", "string")

	// Azure KeyVault Configurations
	ConfigAzureKeyVaultEnabled      = ffc("config.azureKeyVault.enabled", "Whether the Azure Key Vault is enabled", "boolean")
	ConfigAzureKeyVaultURL          = ffc("config.azureKeyVault.vaultURL", "The URL of the Azure Key Vault", "string")
	ConfigAzureKeyVaultClientID     = ffc("config.azureKeyVault.clientID", "The Client ID for the Azure Key Vault", "string")
	ConfigAzureKeyVaultClientSecret = ffc("config.azureKeyVault.clientSecret", "The Client Secret for the Azure Key Vault", "string")
	ConfigAzureKeyVaultTenantID     = ffc("config.azureKeyVault.tenantID", "The Tenant ID for the Azure Key Vault", "string")
	ConfigAzureKeyVaultRemoteSign   = ffc("config.azureKeyVault.remoteSign", "Enable, disable remote sign transactions", "boolean")
	ConfigAzureKeyVault             = ffc("config.azureKeyVault.keyVault", "Enable, disable remote sign transactions", "boolean")
	ConfigAzureSecrets              = ffc("config.azureKeyVault.secrets", "Enable, disable remote sign transactions", "boolean")

	ConfigAzureKeyVaultCacheMaxSize                     = ffc("config.azureKeyVault.cache.maxSize", "The maximum size of the cache for Azure Key Vault", "number")
	ConfigAzureKeyVaultCacheItemsToPrune                = ffc("config.azureKeyVault.cache.itemsToPrune", "The number of items to prune from the cache when it exceeds the maximum size", "number")
	ConfigAzureKeyVaultCacheTTL                         = ffc("config.azureKeyVault.cache.ttl", "The TTL (time-to-live) for cache entries in Azure Key Vault", "duration")
	ConfigAzureKeyVaultMappingKeyAddressEnable          = ffc("config.azureKeyVault.mappingKeyAddress.enabled", "Enable mapping kayname and wallet address", "boolean")
	ConfigAzureKeyVaultMappingKeyAddressRefreshEnabled  = ffc("config.azureKeyVault.mappingKeyAddress.refresh.enabled", "Enable automatic refresh mapping kayname and wallet address", "boolean")
	ConfigAzureKeyVaultMappingKeyAddressRefreshInterval = ffc("config.azureKeyVault.mappingKeyAddress.refresh.interval", "Interval time to automatic refresh", "duration")

	// AWS KMS Configurations
	ConfigAWSWalletEnabled                                   = ffc("config.awsWallet.enabled", "Whether the AWS is enabled", "boolean")
	ConfigAWSWalletRegion                                    = ffc("config.awsWallet.region", "The AWS region where the Secrets and KMS keys are located", "string")
	ConfigAWSWalletAccessKeyID                               = ffc("config.awsWallet.accessKeyID", "The AWS Access Key ID for authentication", "string")
	ConfigAWSWalletSecretAccessKey                           = ffc("config.awsWallet.secretAccessKey", "The AWS Secret Access Key for authentication", "string")
	ConfigAWSWalletSecretsEnabled                            = ffc("config.awsWallet.secrets.enabled", "Enable or disable secrets retrieve used key for address", "boolean")
	ConfigAWSWalletSecretsCacheEnabled                       = ffc("config.awsWallet.secrets.cache.enabled", "Enable or disable secrets cache", "boolean")
	ConfigAWSWalletSecretsCacheMaxSize                       = ffc("config.awsWallet.secrets.cache.maxSize", "The maximum size of the cache for AWS Secrets", "number")
	ConfigAWSWalletSecretsCacheItemsToPrune                  = ffc("config.awsWallet.secrets.cache.itemsToPrune", "The number of items to prune from the cache when it exceeds the maximum size", "number")
	ConfigAWSWalletSecretsCacheTTL                           = ffc("config.awsWallet.secrets.cache.ttl", "The TTL (time-to-live) for cache entries in  AWS Secrets", "duration")
	ConfigAWSWalletKMSEnabled                                = ffc("config.awsWallet.kms.enabled", "Enable or disable KMS operation", "boolean")
	ConfigAWSWalletKMSMemoryMappingAddressKeyRefreshEnabled  = ffc("config.awsWallet.kms.memoryMappingAddressKeyName.refresh.enabled", "Enable automatic refresh mapping kayname and wallet address", "boolean")
	ConfigAWSWalletKMSMemoryMappingAddressKeyRefreshInterval = ffc("config.awsWallet.kms.memoryMappingAddressKeyName.refresh.interval", "Interval time to automatic refresh", "duration")

	// HashiCorp Vault Configurations
	ConfigHashicorpVaultEnabled                          = ffc("config.hashicorpVault.enabled", "Whether the HashiCorp Vault is enabled", "boolean")
	ConfigHashicorpVaultAddress                          = ffc("config.hashicorpVault.address", "The address of the HashiCorp Vault", "string")
	ConfigHashicorpVaultToken                            = ffc("config.hashicorpVault.token", "The token for accessing the HashiCorp Vault", "string")
	ConfigHashicorpVaultSecretsPath                      = ffc("config.hashicorpVault.secretsPath", "The path in Vault where secrets are stored", "string")
	ConfigHashicorpVaultTransitPath                      = ffc("config.hashicorpVault.transitPath", "The path in Vault where transit keys are stored", "string")
	ConfigHashicorpVaultRemoteSign                       = ffc("config.hashicorpVault.remoteSign", "Enable or disable remote sign transactions", "boolean")
	ConfigHashicorpVaultCacheMaxSize                     = ffc("config.hashicorpVault.cache.maxSize", "The maximum size of the cache for HashiCorp Vault", "number")
	ConfigHashicorpVaultCacheItemsToPrune                = ffc("config.hashicorpVault.cache.itemsToPrune", "The number of items to prune from the cache when it exceeds the maximum size", "number")
	ConfigHashicorpVaultCacheTTL                         = ffc("config.hashicorpVault.cache.ttl", "The TTL (time-to-live) for cache entries in HashiCorp Vault", "duration")
	ConfigHashicorpVaultMappingKeyAddressEnable          = ffc("config.hashicorpVault.mappingKeyAddress.enabled", "Enable mapping kayname and wallet address", "boolean")
	ConfigHashicorpVaultMappingKeyAddressRefreshEnabled  = ffc("config.hashicorpVault.mappingKeyAddress.refresh.enabled", "Enable automatic refresh mapping kayname and wallet address", "boolean")
	ConfigHashicorpVaultMappingKeyAddressRefreshInterval = ffc("config.hashicorpVault.mappingKeyAddress.refresh.interval", "Interval time to automatic refresh", "duration")

	ConfigCacheItemsToPrune = ffc("config.cache.itemsToPrune", "The number of items to prune from the cache when it exceeds the maximum size", "number")
	ConfigCacheMaxSize      = ffc("config.cache.maxSize", "The maximum size of the cache for Azure Key Vault", "number")
	ConfigCacheTTL          = ffc("config.cache.ttl", "The TTL (time-to-live) for cache entries in Azure Key Vault", "duration")

	ConfigLocalSignCacheMaxSize      = ffc("config.localSign.cache.maxSize", "The maximum size of the cache for AWS Secrets", "number")
	ConfigLocalSignCacheItemsToPrune = ffc("config.localSign.cache.itemsToPrune", "The number of items to prune from the cache when it exceeds the maximum size", "number")
	ConfigLocalSignCacheTTL          = ffc("config.localSign.cache.ttl", "The TTL (time-to-live) for cache entries in  AWS Secrets", "duration")

	ConfigMappingKeyAddressEnable          = ffc("config.mappingKeyAddress.enabled", "Enable mapping kayname and wallet address", "boolean")
	ConfigMappingKeyAddressRefreshEnabled  = ffc("config.mappingKeyAddress.refresh.enabled", "Enable automatic refresh mapping kayname and wallet address", "boolean")
	ConfigMappingKeyAddressRefreshInterval = ffc("config.mappingKeyAddress.refresh.interval", "Interval time to automatic refresh", "duration")

	MappingKeyAddressEnable          = ffc("mappingKeyAddress.enabled", "Enable mapping kayname and wallet address", "boolean")
	MappingKeyAddressRefreshEnabled  = ffc("mappingKeyAddress.refresh.enabled", "Enable automatic refresh mapping kayname and wallet address", "boolean")
	MappingKeyAddressRefreshInterval = ffc("mappingKeyAddress.refresh.interval", "Interval time to automatic refresh", "duration")

	ConfigKMSEnabled                                = ffc("config.kms.enabled", "Enable or disable KMS operation", "boolean")
	ConfigKMSMemoryMappingAddressKeyRefreshEnabled  = ffc("config.kms.memoryMappingAddressKeyName.refresh.enabled", "Enable automatic refresh mapping kayname and wallet address", "boolean")
	ConfigKMSMemoryMappingAddressKeyRefreshInterval = ffc("config.kms.memoryMappingAddressKeyName.refresh.interval", "Interval time to automatic refresh", "duration")
	ConfigWalletSecretsEnabled                      = ffc("config.secrets.enabled", "Enable or disable secrets retrieve used key for address", "boolean")
	ConfigSecretsCacheEnabled                       = ffc("config.secrets.cache.enabled", "Enable or disable secrets cache", "boolean")
	ConfigWalletSecretsCacheItemsToPrune            = ffc("config.secrets.cache.itemsToPrune", "The number of items to prune from the cache when it exceeds the maximum size", "number")
	ConfigWalletSecretsCacheTTL                     = ffc("config.secrets.cache.ttl", "The TTL (time-to-live) for cache entries in  AWS Secrets", "duration")
	ConfigWalletSecretsCacheMaxSize                 = ffc("config.secrets.cache.maxSize", "The maximum size of the cache for AWS Secrets", "number")
)
