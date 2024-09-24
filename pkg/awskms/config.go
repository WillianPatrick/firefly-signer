package awskms

import (
	"time"

	"github.com/hyperledger/firefly-common/pkg/config"
)

var (
	Region                           = config.AddRootKey("region")
	RemoteSign                       = config.AddRootKey("remoteSign")
	CacheMaxSize                     = config.AddRootKey("cache.maxSize")
	CacheItemsToPrune                = config.AddRootKey("cache.itemsToPrune")
	CacheTTL                         = config.AddRootKey("cache.ttl")
	MappingKeyAddressEnabled         = config.AddRootKey("mappingKeyAddress.enabled")
	MappingKeyAddressRefreshEnabled  = config.AddRootKey("mappingKeyAddress.refresh.enabled")
	MappingKeyAddressRefreshInterval = config.AddRootKey("mappingKeyAddress.refresh.interval")
)

func InitConfig(section config.Section) {
	section.AddKnownKey(string(Region))
	section.AddKnownKey(string(CacheMaxSize))
	section.AddKnownKey(string(CacheItemsToPrune))
	section.AddKnownKey(string(CacheTTL))
	section.AddKnownKey(string(RemoteSign))
	section.AddKnownKey(string(MappingKeyAddressEnabled))
	section.AddKnownKey(string(MappingKeyAddressRefreshEnabled))
	section.AddKnownKey(string(MappingKeyAddressRefreshInterval))
}

func ReadConfig(section config.Section) *Config {
	return &Config{
		Region:     section.GetString(string(Region)),
		RemoteSign: section.GetBool(string(RemoteSign)),
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
	Region            string
	RemoteSign        bool
	Cache             ConfigCache
	MappingKeyAddress MappingKeyAddress
}
