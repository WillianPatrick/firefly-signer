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

package fftypes

import (
	"github.com/santhosh-tekuri/jsonschema/v5"
)

type BaseFFIParamValidator struct{}

var compiledMetaSchema = jsonschema.MustCompileString("ffi.json", `{
	"$ref": "#/$defs/ffiParam",
	"$defs": {
		"integerTypeOptions": {
			"type": "object",
			"properties": {
				"type": {
					"type": "string",
					"enum": [
						"integer",
						"string"
					]
				}
			}
		},
		"numberTypeOptions": {
			"type": "object",
			"properties": {
				"type": {
					"type": "string",
					"enum": [
						"number",
						"string"
					]
				}
			}
		},
		"booleanTypeOptions": {
			"type": "object",
			"properties": {
				"type": {
					"type": "string",
					"enum": [
						"boolean",
						"string"
					]
				}
			}
		},
		"ffiParam": {
			"oneOf": [
				{
					"properties": {
						"type": {
							"type": [
								"string"
							],
							"enum": [
								"boolean",
								"integer",
								"number",
								"string",
								"array",
								"object"
							]
						}
					},
					"required": [
						"type"
					]
				},
				{
					"type": "object",
					"properties": {
						"oneOf": {
							"type": "array",
							"oneOf": [
								{
									"items": {
										"$ref": "#/$defs/integerTypeOptions"
									}
								},
								{
									"items": {
										"$ref": "#/$defs/numberTypeOptions"
									}
								},
								{
									"items": {
										"$ref": "#/$defs/booleanTypeOptions"
									}
								}
							]
						}
					},
					"required": [
						"oneOf"
					]
				}
			]
		}
	}
}`)

func (v BaseFFIParamValidator) Compile(_ jsonschema.CompilerContext, _ map[string]interface{}) (jsonschema.ExtSchema, error) {
	return nil, nil
}

func (v *BaseFFIParamValidator) GetMetaSchema() *jsonschema.Schema {
	return compiledMetaSchema
}

func (v *BaseFFIParamValidator) GetExtensionName() string {
	return "ffi"
}

func NewFFISchemaCompiler() *jsonschema.Compiler {
	c := jsonschema.NewCompiler()
	c.Draft = jsonschema.Draft2020
	v := BaseFFIParamValidator{}
	c.RegisterExtension(v.GetExtensionName(), v.GetMetaSchema(), v)
	return c
}
