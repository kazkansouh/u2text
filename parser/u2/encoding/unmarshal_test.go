/*
 * Copyright (c) 2019 Karim Kanso. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package encoding

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestPropertiesClone(t *testing.T) {
	type test struct {
		name string
		p    properties
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			assert.DeepEqual(t, test.p, test.p.clone())
		}
	}

	tests := []test{
		test{
			name: "nil",
			p:    properties{},
		},
		test{
			name: "nominal",
			p: properties{
				"john": "doe",
				"mr":   "smith",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestPropertiesAppend(t *testing.T) {
	type test struct {
		name     string
		p        properties
		kvs      string
		expected properties
		error    string
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {

			err := test.p.append(test.kvs)

			if test.error == "" {
				assert.NilError(t, err)
			} else {
				assert.ErrorContains(t, err, test.error)
			}

			assert.DeepEqual(t, test.p, test.expected)
		}
	}

	tests := []test{
		test{
			name:     "empty",
			p:        properties{},
			kvs:      "",
			expected: properties{},
			error:    "",
		},
		test{
			name: "add-empty",
			p:    properties{},
			kvs:  "john:doe",
			expected: properties{
				"john": "doe",
			},
			error: "",
		},
		test{
			name: "add-nonempty",
			p: properties{
				"jane": "doe",
			},
			kvs: "john:doe",
			expected: properties{
				"jane": "doe",
				"john": "doe",
			},
			error: "",
		},
		test{
			name: "overwrite",
			p: properties{
				"jane": "doe",
			},
			kvs: "jane:jojo",
			expected: properties{
				"jane": "jojo",
			},
			error: "",
		},
		test{
			name:     "whitespace",
			p:        properties{},
			kvs:      "    ",
			expected: properties{},
			error:    "",
		},
		test{
			name:     "missing-key",
			p:        properties{},
			kvs:      ":value",
			expected: properties{},
			error:    "Invalid tag:",
		},
		test{
			name: "missing-value",
			p:    properties{},
			kvs:  "key:",
			expected: properties{
				"key": "",
			},
			error: "",
		},
		test{
			name:     "no-colon",
			p:        properties{},
			kvs:      "key value",
			expected: properties{},
			error:    "Invalid tag:",
		},
		test{
			name: "multiple-values",
			p:    properties{},
			kvs:  "key1:value1 key2:value2",
			expected: properties{
				"key1": "value1",
				"key2": "value2",
			},
			error: "",
		},
		test{
			name: "multiple-values+space",
			p:    properties{},
			kvs:  "  key1:value1      key2:value2    ",
			expected: properties{
				"key1": "value1",
				"key2": "value2",
			},
			error: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestNewState(t *testing.T) {
	testfunc := func(data []byte) func(*testing.T) {
		return func(t *testing.T) {
			state := newState(data)
			assert.DeepEqual(t, state.data, data)
			assert.Equal(t, state.position, uint(0))
		}
	}

	t.Run("nil", testfunc(nil))
	t.Run("empty", testfunc([]byte{}))
	t.Run("nominal", testfunc([]byte{0x01, 0x02, 0x03}))
}

func TestStateRemain(t *testing.T) {
	type test struct {
		name     string
		data     []byte
		position uint
		remain   uint
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			state := &state{test.data, test.position}
			assert.Equal(t, state.remain(), test.remain)
		}
	}

	tests := []test{
		test{
			name:     "nil",
			data:     nil,
			position: 0,
			remain:   0,
		},
		test{
			name:     "nil-invalid",
			data:     nil,
			position: 1,
			remain:   0,
		},
		test{
			name:     "nominal-start",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			position: 0,
			remain:   5,
		},
		test{
			name:     "nominal-mid",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			position: 3,
			remain:   2,
		},
		test{
			name:     "nominal-penultimate",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			position: 4,
			remain:   1,
		},
		test{
			name:     "nominal-ultimate",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			position: 5,
			remain:   0,
		},
		test{
			name:     "invalid",
			data:     []byte{0x00, 0x00, 0x00, 0x00, 0x00},
			position: 6,
			remain:   0,
		}}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

type UnmarshalerTest struct {
	text string
	f    func(*UnmarshalerTest, []byte) (uint, error)
}

func (x *UnmarshalerTest) UnmarshalC(data []byte) (uint, error) {
	return x.f(x, data)
}

func (x UnmarshalerTest) MarshalText() ([]byte, error) {
	return []byte(x.text), nil
}

func TestUnmarshalPartial(t *testing.T) {
	type test struct {
		name     string
		object   interface{}
		data     []byte
		expected string // json
		used     uint
		error    string
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			n, err := UnmarshalPartial(test.object, test.data)
			if test.error == "" {
				assert.NilError(t, err)
			} else {
				assert.ErrorContains(t, err, test.error)
			}

			assert.Equal(t, n, test.used)

			if test.expected != "NA" {
				var expected interface{}
				assert.NilError(t, json.Unmarshal([]byte(test.expected), &expected))
				actual_bytes, err := json.Marshal(test.object)
				assert.NilError(t, err)
				var actual interface{}
				assert.NilError(t, json.Unmarshal(actual_bytes, &actual))

				assert.DeepEqual(t, expected, actual)
			}
		}
	}

	// allocates uint
	newUint := func(l int) interface{} {
		switch l {
		case 8:
			var x uint8
			return &x
		case 16:
			var x uint16
			return &x
		case 32:
			var x uint32
			return &x
		}
		return nil
	}

	for _, test := range []*test{
		&test{
			name:     "uint32",
			object:   newUint(32),
			data:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: `16909060`,
			used:     4,
			error:    "",
		},
		&test{
			name:     "uint16",
			object:   newUint(16),
			data:     []byte{0x01, 0x02},
			expected: `258`,
			used:     2,
			error:    "",
		},
		&test{
			name:     "uint8",
			object:   newUint(8),
			data:     []byte{0x01},
			expected: `1`,
			used:     1,
			error:    "",
		},
		&test{
			name:     "uint32-short",
			object:   newUint(32),
			data:     []byte{0x01, 0x02},
			expected: `0`,
			used:     0,
			error:    "Stream too short",
		},
		&test{
			name:     "uint32-long",
			object:   newUint(32),
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04},
			expected: `16909060`,
			used:     4,
			error:    "",
		},
		&test{
			name:     "non-ptr",
			object:   uint8(0),
			data:     []byte{0x01},
			expected: `0`,
			used:     0,
			error:    "Invalid pointer",
		},
		&test{
			name: "struct-singleton",
			object: &struct {
				U uint32
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: `{"U": 16909060}`,
			used:     4,
			error:    "",
		},
		&test{
			name: "struct-multi",
			object: &struct {
				U uint32
				V uint16
				W uint8
			}{},
			data: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02,
				0x01,
			},
			expected: `{"U": 16909060, "V": 258, "W": 1}`,
			used:     7,
			error:    "",
		},
		&test{
			name: "struct-nested",
			object: &struct {
				U struct {
					U uint32
				}
				V uint16
				W uint8
			}{},
			data: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02,
				0x01,
			},
			expected: `{"U": {"U": 16909060}, "V": 258, "W": 1}`,
			used:     7,
			error:    "",
		},
		&test{
			name: "slice-nominal",
			object: &struct {
				U []struct {
					X uint32
					Y uint8
				} `u2:"slice-length:4"`
			}{},
			data: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x06, 0x07, 0x08, 0x09, 0x0a,
				0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14,
				0x15, 0x16, 0x17, 0x18, 0x19,
			},
			expected: `{"U": [ {"X": 16909060, "Y": 5} , {"X": 101124105, "Y": 10} , {"X": 185339150, "Y": 15} , {"X": 269554195, "Y": 20}]}`,
			used:     20,
			error:    "",
		},
		&test{
			name: "slice-short",
			object: &struct {
				U []struct {
					X uint32
					Y uint8
				} `u2:"slice-length:4"`
			}{},
			data: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05,
				0x06, 0x07, 0x08, 0x09, 0x0a,
				0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11,
			},
			expected: `NA`,
			used:     15,
			error:    "Stream too short",
		},
		&test{
			name: "slice-no-length",
			object: &struct {
				U []uint32
			}{},
			data:     []byte{0x01, 0x02, 0x03},
			expected: `{"U": null}`,
			used:     0,
			error:    "slice-length not specified",
		},
		&test{
			name: "slice-invalid-length",
			object: &struct {
				U []uint32 `u2:"slice-length:five"`
			}{},
			data:     []byte{0x01, 0x02, 0x03},
			expected: `{"U": null}`,
			used:     0,
			error:    "strconv.Atoi",
		},
		&test{
			name: "slice-negative-length",
			object: &struct {
				U []uint32 `u2:"slice-length:-10"`
			}{},
			data:     []byte{0x01, 0x02, 0x03},
			expected: `{"U": null}`,
			used:     0,
			error:    "slice-length <0",
		},
		&test{
			name: "slice-zero-length",
			object: &struct {
				U []uint32 `u2:"slice-length:0"`
			}{},
			data:     []byte{0x01, 0x02, 0x03},
			expected: `{"U": []}`,
			used:     0,
			error:    "",
		},
		&test{
			name: "byte-slice-nominal",
			object: &struct {
				U []byte `u2:"slice-length:4"`
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: `{"U": "AQIDBA=="}`,
			used:     4,
			error:    "",
		},
		&test{
			name: "byte-slice-short",
			object: &struct {
				U []byte `u2:"slice-length:6"`
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: `{"U": null}`,
			used:     0,
			error:    "Stream too short",
		},
		&test{
			name: "byte-slice-greedy-*",
			object: &struct {
				U []byte `u2:"slice-length:*"`
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: `{"U": "AQIDBAU="}`,
			used:     5,
			error:    "",
		},
		&test{
			name: "byte-slice-greedy-0",
			object: &struct {
				U []byte `u2:"slice-length:0"`
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: `{"U": "AQIDBAU="}`,
			used:     5,
			error:    "",
		},
		&test{
			name: "byte-slice-dynamic",
			object: &struct {
				U []byte `u2:"slice-length:-2"`
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: `{"U": "AQID"}`,
			used:     3,
			error:    "",
		},
		&test{
			name: "byte-slice-dynamic-invalid",
			object: &struct {
				U []byte `u2:"slice-length:-6"`
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: `{"U": null}`,
			used:     0,
			error:    "Stream too short",
		},
		&test{
			name: "struct-ignore",
			object: &struct {
				S string `u2:"ignore:*"`
				T string `u2:"ignore:"`
				U string `u2:"ignore:yes"`
				V uint8
			}{"A", "B", "C", 9},
			data:     []byte{0x01},
			expected: `{"S": "A", "T": "B", "U": "C", "V": 1}`,
			used:     1,
			error:    "",
		},
		&test{
			name: "struct-bad-tag",
			object: &struct {
				S string `u2:"ignore"`
				V uint8
			}{"A", 9},
			data:     []byte{0x01},
			expected: `{"S": "A", "V": 9}`,
			used:     0,
			error:    "Invalid tag",
		},
		&test{
			name: "string-nominal",
			object: &struct {
				U string `u2:"string-length:4"`
			}{},
			data:     []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a},
			expected: `{"U": "hell"}`,
			used:     4,
			error:    "",
		},
		&test{
			name: "string-nominal",
			object: &struct {
				U string `u2:"string-length:4"`
			}{},
			data:     []byte{0x68, 0x65, 0x00, 0x6c, 0x6f, 0x0a},
			expected: `{"U": "he"}`,
			used:     4,
			error:    "",
		},
		&test{
			name: "string-short",
			object: &struct {
				U string `u2:"string-length:4"`
			}{},
			data:     []byte{0x68, 0x65, 0x6c},
			expected: `{"U": ""}`,
			used:     0,
			error:    "Stream too short",
		},
		&test{
			name: "string-no-length",
			object: &struct {
				U string
			}{},
			data:     []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a},
			expected: `{"U": ""}`,
			used:     0,
			error:    "string-length not specified",
		},
		&test{
			name: "string-invalid-length",
			object: &struct {
				U string `u2:"string-length:five"`
			}{},
			data:     []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a},
			expected: `{"U": ""}`,
			used:     0,
			error:    "strconv.Atoi",
		},
		&test{
			name: "string-invalid-length-*",
			object: &struct {
				U string `u2:"string-length:*"`
			}{},
			data:     []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a},
			expected: `{"U": ""}`,
			used:     0,
			error:    "strconv.Atoi",
		},
		&test{
			name: "string-negative-length",
			object: &struct {
				U string `u2:"string-length:-10"`
			}{},
			data:     []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x0a},
			expected: `{"U": ""}`,
			used:     0,
			error:    "string-length <0",
		},
		&test{
			name: "string-zero-length",
			object: &struct {
				U string `u2:"string-length:0"`
			}{},
			data:     []byte{0x01, 0x02, 0x03},
			expected: `{"U": ""}`,
			used:     0,
			error:    "",
		},
		&test{
			name: "unsupported-type",
			object: &struct {
				U int
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: `{"U": 0}`,
			used:     0,
			error:    "Unsupported type",
		},
		&test{
			name: "unmarshaler-basic",
			object: &UnmarshalerTest{
				text: "unexecuted",
				f: func(x *UnmarshalerTest, data []byte) (uint, error) {
					x.text = "executed"
					return 0, nil
				},
			},
			data:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: `"executed"`,
			used:     0,
			error:    "",
		},
		&test{
			name: "unmarshaler-consume",
			object: &UnmarshalerTest{
				text: "unexecuted",
				f: func(x *UnmarshalerTest, data []byte) (uint, error) {
					x.text = "executed"
					return uint(len(data)), nil
				},
			},
			data:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: `"executed"`,
			used:     4,
			error:    "",
		},
		&test{
			name: "unmarshaler-overflow",
			object: &UnmarshalerTest{
				text: "unexecuted",
				f: func(x *UnmarshalerTest, data []byte) (uint, error) {
					x.text = "executed"
					return uint(len(data)) + 1, nil
				},
			},
			data:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: `"executed"`,
			used:     0,
			error:    "Out of bound consumption on UnmarshalC",
		},
	} {
		t.Run(test.name, testfunc(test))
	}
}

func TestReadZero(t *testing.T) {
	state := newState([]byte{})
	assert.Error(t, state.read(reflect.Value{}, properties{}), "Invalid value")
}

func TestUnmarshal(t *testing.T) {
	type test struct {
		name     string
		object   interface{}
		data     []byte
		expected string // json
		error    string
		remain   int
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			stdoutbuf := bytes.Buffer{}
			log.SetOutput(&stdoutbuf)
			defer log.SetOutput(os.Stderr)
			err := Unmarshal(test.object, test.data)
			if test.error == "" {
				assert.NilError(t, err)
			} else {
				assert.ErrorContains(t, err, test.error)
			}

			if test.expected != "NA" {
				var expected interface{}
				assert.NilError(t, json.Unmarshal([]byte(test.expected), &expected))
				actual_bytes, err := json.Marshal(test.object)
				assert.NilError(t, err)
				var actual interface{}
				assert.NilError(t, json.Unmarshal(actual_bytes, &actual))

				assert.DeepEqual(t, expected, actual)
			}

			if test.remain > 0 {
				assert.Assert(t,
					is.Contains(
						string(stdoutbuf.Bytes()),
						fmt.Sprintf("WARNING: %d bytes unused from stream when unmarshalling.", test.remain),
					),
				)
			} else {
				assert.Equal(t, string(stdoutbuf.Bytes()), "")
			}
		}
	}

	for _, test := range []*test{
		&test{
			name: "nominal",
			object: &struct {
				U uint32
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04},
			expected: `{"U": 16909060}`,
			error:    "",
		},
		&test{
			name: "long",
			object: &struct {
				U uint32
			}{},
			data:     []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: `{"U": 16909060}`,
			error:    "",
			remain:   1,
		},
		&test{
			name: "short",
			object: &struct {
				U uint32
			}{},
			data:     []byte{0x01, 0x02, 0x03},
			expected: `{"U": 0}`,
			error:    "Stream too short",
		},
	} {
		t.Run(test.name, testfunc(test))
	}
}
