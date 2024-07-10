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
	"encoding/json"
	"fmt"
	"io"

	"github.com/hyperledger/firefly-common/pkg/fftypes"
	"github.com/hyperledger/firefly-signer/pkg/ethtypes"
	"github.com/hyperledger/firefly-signer/pkg/secp256k1"
	"golang.org/x/crypto/sha3"
)

const (
	version3        = 3
	cipherAES128ctr = "aes-128-ctr"
	kdfTypeScrypt   = "scrypt"
	kdfTypePbkdf2   = "pbkdf2"
	nLight          = 1 << 12
	nStandard       = 1 << 10
	pDefault        = 1
)

type WalletFile interface {
	KeyPair() *secp256k1.KeyPair
	JSON() []byte
}

type kdfParamsScrypt struct {
	DKLen int                    `json:"dklen"`
	N     int                    `json:"n"`
	P     int                    `json:"p"`
	R     int                    `json:"r"`
	Salt  ethtypes.HexBytesPlain `json:"salt"`
}

type kdfParamsPbkdf2 struct {
	DKLen int                    `json:"dklen"`
	C     int                    `json:"c"`
	PRF   string                 `json:"prf"`
	Salt  ethtypes.HexBytesPlain `json:"salt"`
}

type cipherParams struct {
	IV ethtypes.HexBytesPlain `json:"iv"`
}

type cryptoCommon struct {
	Cipher       string                 `json:"cipher"`
	CipherText   ethtypes.HexBytesPlain `json:"ciphertext"`
	CipherParams cipherParams           `json:"cipherparams"`
	KDF          string                 `json:"kdf"`
	MAC          ethtypes.HexBytesPlain `json:"mac"`
}

type cryptoScrypt struct {
	cryptoCommon
	KDFParams kdfParamsScrypt `json:"kdfparams"`
}

type cryptoPbkdf2 struct {
	cryptoCommon
	KDFParams kdfParamsPbkdf2 `json:"kdfparams"`
}

type walletFileBase struct {
	Address ethtypes.AddressPlainHex `json:"address"`
	ID      *fftypes.UUID            `json:"id"`
	Version int                      `json:"version"`

	keypair *secp256k1.KeyPair
}

type walletFileCommon struct {
	walletFileBase
	Crypto cryptoCommon `json:"crypto"`
}

type walletFilePbkdf2 struct {
	walletFileBase
	Crypto cryptoPbkdf2 `json:"crypto"`
}

type walletFileScrypt struct {
	walletFileBase
	Crypto cryptoScrypt `json:"crypto"`
}

func (w *walletFileBase) KeyPair() *secp256k1.KeyPair {
	return w.keypair
}

func (w *walletFilePbkdf2) JSON() []byte {
	b, _ := json.Marshal(w)
	return b
}

func (w *walletFileScrypt) JSON() []byte {
	b, _ := json.Marshal(w)
	return b
}

func NewWalletFileLight(password string, keypair *secp256k1.KeyPair) WalletFile {
	return newScryptWalletFile(password, keypair, nLight, pDefault)
}

func NewWalletFileStandard(password string, keypair *secp256k1.KeyPair) WalletFile {
	return newScryptWalletFile(password, keypair, nStandard, pDefault)
}

func ReadWalletFile(jsonWallet []byte, password []byte) (WalletFile, error) {
	var w walletFileCommon
	if err := json.Unmarshal(jsonWallet, &w); err != nil {
		return nil, fmt.Errorf("invalid wallet file: %s", err)
	}
	if w.ID == nil {
		return nil, fmt.Errorf("missing keyfile id")
	}
	if w.Version != version3 {
		return nil, fmt.Errorf("incorrect keyfile version (only V3 supported): %d", w.Version)
	}
	switch w.Crypto.KDF {
	case kdfTypeScrypt:
		return readScryptWalletFile(jsonWallet, password)
	case kdfTypePbkdf2:
		return readPbkdf2WalletFile(jsonWallet, password)
	default:
		return nil, fmt.Errorf("unsupported kdf: %s", w.Crypto.KDF)
	}
}

func mustReadBytes(size int, r io.Reader) []byte {
	b := make([]byte, size)
	n, err := io.ReadFull(r, b)
	if err != nil || n != size {
		panic(fmt.Sprintf("Read failed (len=%d): %s", n, err))
	}
	return b
}

func generateMac(derivedKeyMacBytes []byte, cipherText []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(derivedKeyMacBytes)
	hash.Write(cipherText)
	return hash.Sum(nil)
}
