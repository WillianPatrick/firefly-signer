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

package keystorev3

import (
	"bytes"
	"fmt"
)

func (c *cryptoCommon) decryptCommon(derivedKey []byte) ([]byte, error) {
	if len(derivedKey) != 32 {
		return nil, fmt.Errorf("invalid scrypt keystore: derived key length %d != 32", len(derivedKey))
	}
	// Last 16 bytes of derived key are used for MAC
	derivedMac := generateMac(derivedKey[16:32], c.CipherText)
	if !bytes.Equal(derivedMac, c.MAC) {
		return nil, fmt.Errorf("invalid password provided")
	}
	// First 16 bytes of derived key are used as the encryption key
	encryptKey := derivedKey[0:16]
	return aes128CtrDecrypt(encryptKey, c.CipherParams.IV, c.CipherText)
}
