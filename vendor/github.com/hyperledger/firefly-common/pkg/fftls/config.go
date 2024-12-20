// Copyright © 2023 Kaleido, Inc.
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

package fftls

import (
	"github.com/hyperledger/firefly-common/pkg/config"
)

const (
	// HTTPConfTLSCAFile the TLS certificate authority file for the HTTP server
	HTTPConfTLSCAFile = "caFile"
	// HTTPConfTLSCertFile the TLS certificate file for the HTTP server
	HTTPConfTLSCertFile = "certFile"
	// HTTPConfTLSClientAuth whether the HTTP server requires a mutual TLS connection
	HTTPConfTLSClientAuth = "clientAuth"
	// HTTPConfTLSEnabled whether TLS is enabled for the HTTP server
	HTTPConfTLSEnabled = "enabled"
	// HTTPConfTLSKeyFile the private key file for TLS on the server
	HTTPConfTLSKeyFile = "keyFile"
	// HTTPConfTLSInsecureSkipHostVerify disables host verification - insecure (for dev only)
	HTTPConfTLSInsecureSkipHostVerify = "insecureSkipHostVerify"

	// HTTPConfTLSRequiredDNAttributes provides a set of regular expressions, to match against the DN of the client. Requires HTTPConfTLSClientAuth
	HTTPConfTLSRequiredDNAttributes = "requiredDNAttributes"

	defaultHTTPTLSEnabled = false
)

type Config struct {
	Enabled                bool                   `ffstruct:"tlsconfig" json:"enabled"`
	ClientAuth             bool                   `ffstruct:"tlsconfig" json:"clientAuth,omitempty"`
	CAFile                 string                 `ffstruct:"tlsconfig" json:"caFile,omitempty"`
	CertFile               string                 `ffstruct:"tlsconfig" json:"certFile,omitempty"`
	KeyFile                string                 `ffstruct:"tlsconfig" json:"keyFile,omitempty"`
	InsecureSkipHostVerify bool                   `ffstruct:"tlsconfig" json:"insecureSkipHostVerify"`
	RequiredDNAttributes   map[string]interface{} `ffstruct:"tlsconfig" json:"requiredDNAttributes,omitempty"`
}

func InitTLSConfig(conf config.Section) {
	conf.AddKnownKey(HTTPConfTLSEnabled, defaultHTTPTLSEnabled)
	conf.AddKnownKey(HTTPConfTLSCAFile)
	conf.AddKnownKey(HTTPConfTLSClientAuth)
	conf.AddKnownKey(HTTPConfTLSCertFile)
	conf.AddKnownKey(HTTPConfTLSKeyFile)
	conf.AddKnownKey(HTTPConfTLSRequiredDNAttributes)
	conf.AddKnownKey(HTTPConfTLSInsecureSkipHostVerify)
}

func GenerateConfig(conf config.Section) *Config {
	return &Config{
		Enabled:                conf.GetBool(HTTPConfTLSEnabled),
		ClientAuth:             conf.GetBool(HTTPConfTLSClientAuth),
		CAFile:                 conf.GetString(HTTPConfTLSCAFile),
		CertFile:               conf.GetString(HTTPConfTLSCertFile),
		KeyFile:                conf.GetString(HTTPConfTLSKeyFile),
		InsecureSkipHostVerify: conf.GetBool(HTTPConfTLSInsecureSkipHostVerify),
		RequiredDNAttributes:   conf.GetObject(HTTPConfTLSRequiredDNAttributes),
	}
}
