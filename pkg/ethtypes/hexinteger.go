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

package ethtypes

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/hyperledger/firefly-common/pkg/i18n"
)

// HexInteger is a positive integer - serializes to JSON as an 0x hex string (no leading zeros), and parses flexibly depending on the prefix (so 0x for hex, or base 10 for plain string / float64)
type HexInteger big.Int

func (h *HexInteger) String() string {
	return "0x" + (*big.Int)(h).Text(16)
}

func (h HexInteger) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, h.String())), nil
}

func (h *HexInteger) UnmarshalJSON(b []byte) error {
	var i interface{}
	_ = json.Unmarshal(b, &i)
	switch i := i.(type) {
	case float64:
		*h = HexInteger(*big.NewInt(int64(i)))
		return nil
	case string:
		bi, ok := new(big.Int).SetString(i, 0)
		if !ok {
			return fmt.Errorf("unable to parse integer: %s", i)
		}
		if bi.Sign() < 0 {
			return fmt.Errorf("negative values are not supported: %s", i)
		}
		*h = HexInteger(*bi)
		return nil
	default:
		return fmt.Errorf("unable to parse integer from type %T", i)
	}
}

func (h *HexInteger) BigInt() *big.Int {
	if h == nil {
		return new(big.Int)
	}
	return (*big.Int)(h)
}

func (h *HexInteger) Uint64() uint64 {
	return h.BigInt().Uint64()
}

func (h *HexInteger) Int64() int64 {
	return h.BigInt().Int64()
}

func NewHexIntegerU64(i uint64) *HexInteger {
	return (*HexInteger)(big.NewInt(0).SetUint64(i))
}

func NewHexInteger64(i int64) *HexInteger {
	return (*HexInteger)(big.NewInt(i))
}

func NewHexInteger(i *big.Int) *HexInteger {
	return (*HexInteger)(i)
}

func (h *HexInteger) Scan(src interface{}) error {
	switch src := src.(type) {
	case nil:
		return nil
	case int64:
		*h = *NewHexInteger64(src)
		return nil
	case uint64:
		*h = *NewHexIntegerU64(src)
		return nil
	default:
		return i18n.NewError(context.Background(), i18n.MsgTypeRestoreFailed, src, h)
	}
}
