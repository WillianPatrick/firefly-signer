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
	"crypto/ecdsa"
	"sync"
)

type pubKeyCache struct {
	pubKeys map[string]*ecdsa.PublicKey
	mutex   sync.RWMutex
}

func newPubKeyCache() *pubKeyCache {
	return &pubKeyCache{
		pubKeys: make(map[string]*ecdsa.PublicKey),
	}
}

func (c *pubKeyCache) Add(keyID string, key *ecdsa.PublicKey) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	c.pubKeys[keyID] = key
}

func (c *pubKeyCache) Get(keyID string) *ecdsa.PublicKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return c.pubKeys[keyID]
}
