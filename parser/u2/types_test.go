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

package u2

import (
	"testing"
	"time"

	"gotest.tools/assert"
)

func TestOriginalPacketData(t *testing.T) {
	b := []byte("hello")
	pkt := Unified2Packet{
		packet_data: b,
	}

	assert.DeepEqual(t, pkt.OriginalPacketData(), b)
}

func TestIPv4UnmarshalC(t *testing.T) {
	type test struct {
		name     string
		input    []byte
		error    string
		expected IPv4
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			ip := IPv4{}
			n, err := ip.UnmarshalC(test.input)
			if test.error != "" {
				assert.ErrorContains(t, err, test.error)
				assert.Equal(t, n, uint(0))
			} else {
				assert.NilError(t, err)
				assert.Equal(t, n, uint(4))
			}
			assert.DeepEqual(t, ip, test.expected)
		}
	}

	tests := []test{
		test{
			name:     "nominal",
			input:    []byte{0x01, 0x02, 0x03, 0x04},
			error:    "",
			expected: []byte{0x01, 0x02, 0x03, 0x04},
		},
		test{
			name:     "nil",
			input:    nil,
			error:    "Stream too short to parse IPv4",
			expected: []byte{},
		},
		test{
			name:     "short",
			input:    []byte{0x01, 0x02, 0x03},
			error:    "Stream too short to parse IPv4",
			expected: []byte{},
		},
		test{
			name:     "long",
			input:    []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			error:    "",
			expected: []byte{0x01, 0x02, 0x03, 0x04},
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestIPv6UnmarshalC(t *testing.T) {
	type test struct {
		name     string
		input    []byte
		error    string
		expected IPv6
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			ip := IPv6{}
			n, err := ip.UnmarshalC(test.input)
			if test.error != "" {
				assert.ErrorContains(t, err, test.error)
				assert.Equal(t, n, uint(0))
			} else {
				assert.NilError(t, err)
				assert.Equal(t, n, uint(16))
			}
			assert.DeepEqual(t, ip, test.expected)
		}
	}

	tests := []test{
		test{
			name: "nominal",
			input: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
			error: "",
			expected: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
		},
		test{
			name:     "nil",
			input:    nil,
			error:    "Stream too short to parse IPv6",
			expected: []byte{},
		},
		test{
			name:     "short",
			input:    []byte{0x01, 0x02, 0x03},
			error:    "Stream too short to parse IPv6",
			expected: []byte{},
		},
		test{
			name: "long",
			input: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			},
			error: "",
			expected: []byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
				0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestTimeUnmarshalC(t *testing.T) {
	type test struct {
		name     string
		input    []byte
		error    string
		expected Time
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			time := Time{}
			n, err := time.UnmarshalC(test.input)
			if test.error != "" {
				assert.ErrorContains(t, err, test.error)
				assert.Equal(t, n, uint(0))
			} else {
				assert.NilError(t, err)
				assert.Equal(t, n, uint(8))
			}
			assert.DeepEqual(t, time, test.expected)
		}
	}

	tests := []test{
		test{
			name: "nominal",
			input: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
			},
			error: "",
			expected: Time{
				Second:      0x1020304,
				Microsecond: 0x1020304,
				Time:        time.Unix(int64(0x1020304), int64(0x1020304)*1000),
			},
		},
		test{
			name:  "nil",
			input: nil,
			error: "Stream too short ",
			expected: Time{
				Second:      0,
				Microsecond: 0,
			},
		},
		test{
			name:  "short",
			input: []byte{0x01, 0x02, 0x03, 0x04},
			error: "Stream too short ",
			expected: Time{
				Second:      0,
				Microsecond: 0,
			},
		},
		test{
			name: "long",
			input: []byte{
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
				0x01, 0x02, 0x03, 0x04,
			},
			error: "",
			expected: Time{
				Second:      0x1020304,
				Microsecond: 0x1020304,
				Time:        time.Unix(int64(0x1020304), int64(0x1020304)*1000),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestBlockedUnmarshalC(t *testing.T) {
	type test struct {
		name     string
		input    []byte
		error    string
		expected Blocked
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			b := Blocked("")
			n, err := b.UnmarshalC(test.input)
			if test.error != "" {
				assert.ErrorContains(t, err, test.error)
				assert.Equal(t, n, uint(0))
			} else {
				assert.NilError(t, err)
				assert.Equal(t, n, uint(1))
			}
			assert.Equal(t, b, test.expected)
		}
	}

	tests := []test{
		test{
			name:     "nominal-not-dropped",
			input:    []byte{0x00},
			error:    "",
			expected: "Was NOT Dropped",
		},
		test{
			name:     "nominal-dropped",
			input:    []byte{0x01},
			error:    "",
			expected: "Was Dropped",
		},
		test{
			name:     "nominal-would-dropped",
			input:    []byte{0x02},
			error:    "",
			expected: "Would Have Dropped",
		},
		test{
			name:     "out-of-range",
			input:    []byte{0x03},
			error:    "Out of range value for blocked field",
			expected: "",
		},
		test{
			name:     "nil",
			input:    nil,
			error:    "Stream too short to parse blocked",
			expected: "",
		},
		test{
			name:     "short",
			input:    []byte{},
			error:    "Stream too short to parse blocked",
			expected: "",
		},
		test{
			name:     "long",
			input:    []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			error:    "",
			expected: "Was Dropped",
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}
