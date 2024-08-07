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

package abi

import (
	"context"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExampleABIEncode1(t *testing.T) {

	f := &Entry{
		Name: "baz",
		Inputs: ParameterArray{
			{Type: "uint32"},
			{Type: "bool"},
		},
	}

	cv, err := f.Inputs.ParseJSON([]byte(`[
		69,
		true
	]`))
	assert.NoError(t, err)

	data, err := f.EncodeCallData(cv)
	assert.NoError(t, err)

	assert.Equal(t, "cdcd77c0"+
		"0000000000000000000000000000000000000000000000000000000000000045"+
		"0000000000000000000000000000000000000000000000000000000000000001",
		hex.EncodeToString(data))

}

func TestExampleABIEncode2(t *testing.T) {

	f := &Entry{
		Name: "bar",
		Inputs: ParameterArray{
			{Type: "bytes3[2]"},
		},
	}

	cv, err := f.Inputs.ParseJSON([]byte(`[
		["` + hex.EncodeToString([]byte("abc")) + `", "` + hex.EncodeToString([]byte("def")) + `"]
	]`))
	assert.NoError(t, err)

	data, err := f.EncodeCallData(cv)
	assert.NoError(t, err)

	assert.Equal(t, "fce353f6"+
		"6162630000000000000000000000000000000000000000000000000000000000"+ // first fixed-length entry in static array
		"6465660000000000000000000000000000000000000000000000000000000000", // second fixed-length in static array
		hex.EncodeToString(data))

}

func TestExampleABIEncode3(t *testing.T) {

	f := &Entry{
		Name: "sam",
		Inputs: ParameterArray{
			{Type: "bytes"},
			{Type: "bool"},
			{Type: "uint[]"},
		},
	}

	cv, err := f.Inputs.ParseJSON([]byte(`[
		"` + hex.EncodeToString([]byte("dave")) + `",
		true,
		[ 1, 2, 3 ]
	]`))
	assert.NoError(t, err)

	data, err := f.EncodeCallData(cv)
	assert.NoError(t, err)

	assert.Equal(t, "a5643bf2"+
		// head
		"0000000000000000000000000000000000000000000000000000000000000060"+ // location of data for 1st param
		"0000000000000000000000000000000000000000000000000000000000000001"+ // boolean true
		"00000000000000000000000000000000000000000000000000000000000000a0"+ // location of data for 3rd param
		// 1st param (dynamic)
		"0000000000000000000000000000000000000000000000000000000000000004"+ // length in bytes
		"6461766500000000000000000000000000000000000000000000000000000000"+ // "dave" padded right
		// 3rd param (dynamic)
		"0000000000000000000000000000000000000000000000000000000000000003"+ // length of array
		"0000000000000000000000000000000000000000000000000000000000000001"+ // first value
		"0000000000000000000000000000000000000000000000000000000000000002"+ // second value
		"0000000000000000000000000000000000000000000000000000000000000003", // third value
		hex.EncodeToString(data))

}

func TestExampleABIEncode4(t *testing.T) {

	f := &Entry{
		Name: "f",
		Inputs: ParameterArray{
			{Type: "uint"},
			{Type: "uint32[]"},
			{Type: "bytes10"},
			{Type: "bytes"},
		},
	}

	cv, err := f.Inputs.ParseJSON([]byte(`[
		"0x123",
		["0x456","0x789"],
		"` + hex.EncodeToString([]byte("1234567890")) + `",
		"` + hex.EncodeToString([]byte("Hello, world!")) + `"
	]`))
	assert.NoError(t, err)

	data, err := f.EncodeCallData(cv)
	assert.NoError(t, err)

	assert.Equal(t, "8be65246"+
		// head
		"0000000000000000000000000000000000000000000000000000000000000123"+ // 0x123 padded to 32 b
		"0000000000000000000000000000000000000000000000000000000000000080"+ // offset of start of 2nd param
		"3132333435363738393000000000000000000000000000000000000000000000"+ // 0x1234567890 padded to 32 b
		"00000000000000000000000000000000000000000000000000000000000000e0"+ // offset of start of 4th param
		// 2nd param (dynamic)
		"0000000000000000000000000000000000000000000000000000000000000002"+ // 2 elements in array
		"0000000000000000000000000000000000000000000000000000000000000456"+ // first element
		"0000000000000000000000000000000000000000000000000000000000000789"+ // second element
		// 4th param (dynamic)
		"000000000000000000000000000000000000000000000000000000000000000d"+ // 13 bytes
		"48656c6c6f2c20776f726c642100000000000000000000000000000000000000", // the string
		hex.EncodeToString(data))

}

func TestExampleABIEncode5(t *testing.T) {

	f := &Entry{
		Name: "g",
		Inputs: ParameterArray{
			{Type: "uint[][]"},
			{Type: "string[]"},
		},
	}

	cv, err := f.Inputs.ParseJSON([]byte(`[
		[ [1,2], [3] ],
		[ "one", "two", "three" ]
	]`))
	assert.NoError(t, err)

	data, err := f.EncodeCallData(cv)
	assert.NoError(t, err)

	assert.Equal(t, "2289b18c"+
		// head
		"0000000000000000000000000000000000000000000000000000000000000040"+ // offset of [[1, 2], [3]]
		"0000000000000000000000000000000000000000000000000000000000000140"+ // offset of ["one", "two", "three"]
		"0000000000000000000000000000000000000000000000000000000000000002"+ // count for [[1, 2], [3]]
		"0000000000000000000000000000000000000000000000000000000000000040"+ // offset of [1, 2]
		"00000000000000000000000000000000000000000000000000000000000000a0"+ // offset of [3]
		"0000000000000000000000000000000000000000000000000000000000000002"+ // count for [1, 2]
		"0000000000000000000000000000000000000000000000000000000000000001"+ // encoding of 1
		"0000000000000000000000000000000000000000000000000000000000000002"+ // encoding of 2
		"0000000000000000000000000000000000000000000000000000000000000001"+ // count for [3]
		"0000000000000000000000000000000000000000000000000000000000000003"+ // encoding of 3
		"0000000000000000000000000000000000000000000000000000000000000003"+ // count for ["one", "two", "three"]
		"0000000000000000000000000000000000000000000000000000000000000060"+ // offset for "one"
		"00000000000000000000000000000000000000000000000000000000000000a0"+ // offset for "two"
		"00000000000000000000000000000000000000000000000000000000000000e0"+ // offset for "three"
		"0000000000000000000000000000000000000000000000000000000000000003"+ // count for "one"
		"6f6e650000000000000000000000000000000000000000000000000000000000"+ // encoding of "one"
		"0000000000000000000000000000000000000000000000000000000000000003"+ // count for "two"
		"74776f0000000000000000000000000000000000000000000000000000000000"+ // encoding of "two"
		"0000000000000000000000000000000000000000000000000000000000000005"+ // count for "three"
		"7468726565000000000000000000000000000000000000000000000000000000", // encoding of "three"
		hex.EncodeToString(data))

}

func TestEncodeBytesFixed(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "bytes32"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	hexStr := "090807060504030201000908070605040302010009080706050403020100feed"
	b, err := hex.DecodeString(hexStr)
	data, dynamic, err := encodeABIBytes(context.Background(), "test", bytes32Component, b)
	assert.NoError(t, err)
	assert.False(t, dynamic)
	assert.Equal(t, hexStr, hex.EncodeToString(data))

}

func TestEncodeBytesDynamicExact32(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "bytes"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	lenHexStr := "0000000000000000000000000000000000000000000000000000000000000020"
	hexStr := "090807060504030201000908070605040302010009080706050403020100feed"
	b, err := hex.DecodeString(hexStr)
	data, dynamic, err := encodeABIBytes(context.Background(), "test", bytes32Component, b)
	assert.NoError(t, err)
	assert.True(t, dynamic)
	assert.Equal(t, lenHexStr+hexStr, hex.EncodeToString(data))

}

func TestEncodeBytesDynamicLess32(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "bytes"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	lenHexStr := "0000000000000000000000000000000000000000000000000000000000000004"
	hexStr := "feedbeef"
	hexStrPadded := "feedbeef00000000000000000000000000000000000000000000000000000000"
	b, err := hex.DecodeString(hexStr)
	data, dynamic, err := encodeABIBytes(context.Background(), "test", bytes32Component, b)
	assert.NoError(t, err)
	assert.True(t, dynamic)
	assert.Equal(t, lenHexStr+hexStrPadded, hex.EncodeToString(data))

}

func TestEncodeBytesDynamicMore32(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "string"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	lenHexStr := "0000000000000000000000000000000000000000000000000000000000000031"
	hexStr := "09080706050403020100090807060504030201000908070605040302010090807060504030201009080706050403020100"
	hexStrPadded := "09080706050403020100090807060504030201000908070605040302010090807060504030201009080706050403020100000000000000000000000000000000"
	b, err := hex.DecodeString(hexStr)
	data, dynamic, err := encodeABIBytes(context.Background(), "test", bytes32Component, b)
	assert.NoError(t, err)
	assert.True(t, dynamic)
	assert.Equal(t, lenHexStr+hexStrPadded, hex.EncodeToString(data))

}

func TestEncodeStringWrongType(t *testing.T) {

	_, _, err := encodeABIString(context.Background(), "test", nil, 12345)
	assert.Regexp(t, "FF22042", err)

}

func TestEncodeStringShort(t *testing.T) {

	lenHexStr := "000000000000000000000000000000000000000000000000000000000000000d"
	hexStr := "48656c6c6f2c20776f726c642100000000000000000000000000000000000000"
	data, dynamic, err := encodeABIString(context.Background(), "test", nil, "Hello, world!")
	assert.NoError(t, err)
	assert.True(t, dynamic)
	assert.Equal(t, lenHexStr+hexStr, hex.EncodeToString(data))

}

func TestEncodeBytesFunction(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "function"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	hexStr := "72b88e6bd5be978cae4c29f83b0d7d360d255d42fce353f6"
	b, err := hex.DecodeString(hexStr)
	data, dynamic, err := encodeABIBytes(context.Background(), "test", bytes32Component, b)
	assert.NoError(t, err)
	assert.False(t, dynamic)
	assert.Equal(t, hexStr+"0000000000000000" /* padded 24 to 32 */, hex.EncodeToString(data))

}

func TestEncodeBytesFixedInsufficientInput(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "bytes32"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	hexStr := "090807060504030201000908070605040302010009080706050403020100fe" // only 31 bytes
	b, err := hex.DecodeString(hexStr)
	_, _, err = encodeABIBytes(context.Background(), "test", bytes32Component, b)
	assert.Regexp(t, "FF22043", err)

}

func TestEncodeBytesFixedWrongType(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "bytes32"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	_, _, err = encodeABIBytes(context.Background(), "test", bytes32Component, 12345)
	assert.Regexp(t, "FF22042", err)

}

func TestEncodeSignedIntegerWrongType(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	_, _, err = encodeABISignedInteger(context.Background(), "test", bytes32Component, 12345)
	assert.Regexp(t, "FF22042", err)

}

func TestEncodeSignedIntegerPositiveOk(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	data, dynamic, err := encodeABISignedInteger(context.Background(), "test", bytes32Component, posMax[256])
	assert.NoError(t, err)
	assert.False(t, dynamic)
	assert.Equal(t, "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", hex.EncodeToString(data))

}

func TestEncodeSignedIntegerNegativeOk(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	data, dynamic, err := encodeABISignedInteger(context.Background(), "test", bytes32Component, negMax[256])
	assert.NoError(t, err)
	assert.False(t, dynamic)
	assert.Equal(t, "8000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(data))

}

func TestEncodeSignedIntegerTooLarge(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	i := new(big.Int).Add(posMax[256], big.NewInt(1))
	_, _, err = encodeABISignedInteger(context.Background(), "test", bytes32Component, i)
	assert.Regexp(t, "FF22044", err)

}

func TestEncodeSignedIntegerTooSmall(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	i := new(big.Int).Sub(negMax[256], big.NewInt(1))
	_, _, err = encodeABISignedInteger(context.Background(), "test", bytes32Component, i)
	assert.Regexp(t, "FF22044", err)

}

func TestEncodeUnsignedIntegerWrongType(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	_, _, err = encodeABIUnsignedInteger(context.Background(), "test", bytes32Component, 12345)
	assert.Regexp(t, "FF22042", err)

}

func TestEncodeUnsignedIntegerPositiveOk(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	twoPow256minus1 := new(big.Int).Sub(new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil), big.NewInt(1))
	data, dynamic, err := encodeABIUnsignedInteger(context.Background(), "test", bytes32Component, twoPow256minus1)
	assert.NoError(t, err)
	assert.False(t, dynamic)
	assert.Equal(t, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", hex.EncodeToString(data))

}

func TestEncodeUnsignedIntegerNegativeFail(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	twoPow256minus1 := big.NewInt(-1)
	_, _, err = encodeABIUnsignedInteger(context.Background(), "test", bytes32Component, twoPow256minus1)
	assert.Regexp(t, "FF22062", err)

}

func TestEncodeUnsignedIntegerTooLarge(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "int256"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	twoPow256 := new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil)
	_, _, err = encodeABIUnsignedInteger(context.Background(), "test", bytes32Component, twoPow256)
	assert.Regexp(t, "FF22044", err)

}

func TestEncodeUnsignedFloatPositiveOk(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "ufixed128x18"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	f, _ := new(big.Float).SetString("1.012345678901234567")
	data, dynamic, err := encodeABIUnsignedFloat(context.Background(), "test", bytes32Component, f)
	assert.NoError(t, err)
	assert.False(t, dynamic)
	i, _ := new(big.Int).SetString("1012345678901234567", 10)
	ib32 := make([]byte, 32)
	i.FillBytes(ib32)
	assert.Equal(t, hex.EncodeToString(ib32), hex.EncodeToString(data))

}

func TestEncodeUnsignedFloatNegativeOk(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "fixed128x18"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	f, _ := new(big.Float).SetString("-1.012345678901234567")
	data, dynamic, err := encodeABISignedFloat(context.Background(), "test", bytes32Component, f)
	assert.NoError(t, err)
	assert.False(t, dynamic)
	i, _ := new(big.Int).SetString("1012345678901234567", 10)
	ib32 := SerializeInt256TwosComplementBytes(i)
	assert.Equal(t, hex.EncodeToString(ib32), hex.EncodeToString(data))

}

func TestEncodeSignedFlowWrongType(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "fixed128x18"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	_, _, err = encodeABISignedFloat(context.Background(), "test", bytes32Component, 12345)
	assert.Regexp(t, "FF22042", err)

}

func TestEncodeUnsignedFlowWrongType(t *testing.T) {

	bytes32Component, err := (&Parameter{Type: "ufixed128x18"}).parseABIParameterComponents(context.Background())
	assert.NoError(t, err)

	_, _, err = encodeABIUnsignedFloat(context.Background(), "test", bytes32Component, 12345)
	assert.Regexp(t, "FF22042", err)

}

func TestEncodeABIDataBadCV(t *testing.T) {
	_, _, err := (&ComponentValue{}).encodeABIData(context.Background(), "")
	assert.Regexp(t, "FF22041", err)
}

func TestEncodeABIDataBadCVType(t *testing.T) {
	_, _, err := (&ComponentValue{
		Component: &typeComponent{
			cType: -99,
		},
	}).encodeABIData(context.Background(), "")
	assert.Regexp(t, "FF22041", err)
}

func TestEncodeABIDataBadCVChild(t *testing.T) {
	_, _, err := (&ComponentValue{
		Component: &typeComponent{
			cType: TupleComponent,
		},
		Children: []*ComponentValue{
			{},
		},
	}).encodeABIData(context.Background(), "")
	assert.Regexp(t, "FF22041", err)
}
