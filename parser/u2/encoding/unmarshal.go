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

// Defines an decoding that is similar to encoding/binary.
//
// Decodes structs written in C with big-endian that consist of basic
// types which include uint8/16/32, byte slices (or variable sizes) and
// strings (null terminated with a max length).
//
// Slices must have the tag:
//
//   u2:"slice-length:n"
//
// where n is the desired length (must be positive).
//
// Byte slices can have the length specified as negative (bytes from
// end of stream). Thus, a length of "0" or "*" means consume all
// remaining bytes into the slice.
//
// Strings must have the tag:
//
//   u2:"string-length:n"
//
// where n is the maximum length (must be positive). If a null byte is
// consumed before n, then the string will stop at that point but all
// n bytes will be consumed from the stream.
//
// Any field marked with the tag:
//
//   u2:"ignore:*"
//
// will be skipped over (the * can be any value). That is, it will not
// consume any bytes from the input stream.
package encoding

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// Types in other packages can implement this to provide a custom
// encoding
type Unmarshaler interface {
	UnmarshalC([]byte) (uint, error)
}

type properties map[string]string

func (p properties) clone() properties {
	q := map[string]string{}
	for k, v := range p {
		q[k] = v
	}
	return q
}

// Adds string of the form:
//    "key1:value1 key2:value2"
func (p properties) append(kvs string) error {
	s := strings.Split(kvs, " ")
	for _, v := range s {
		kv := strings.SplitN(v, ":", 2)
		if len(kv) == 2 && kv[0] != "" {
			p[kv[0]] = kv[1]
		} else {
			if v != "" {
				return fmt.Errorf("Invalid tag: %q", v)
			}
		}
	}
	return nil
}

type state struct {
	data     []byte
	position uint
}

func (s *state) remain() uint {
	if l := uint(len(s.data)); l > s.position {
		return l - s.position
	}
	return 0
}

// Unmarshal data into the structure passed in to x.
//
// Returns number of bytes consumed, or an error (typically as the
// data slice is too small) in which case x might have been partially
// populated and some bytes consumed. For example, in the case of a
// struct or non-byte slice its possible that members will be parsed
// and assigned to relevant locations until an error occours. In which
// case, the uint returned will be the last successful parse.
func UnmarshalPartial(x interface{}, data []byte) (uint, error) {
	s := newState(data)

	v := reflect.ValueOf(x)

	if v.Kind() != reflect.Ptr || v.IsNil() {
		return s.position, errors.New("Invalid pointer")
	}

	err := s.read(v, properties{})
	return s.position, err
}

type UnmarshalWarning []byte

func (bytes UnmarshalWarning) Error() string {
	return fmt.Sprintf("%d bytes unused from stream when unmarshalling", len(bytes))
}

// See UnmarshalPartial. In addition, in the case that not all bytes
// from data are consumed, Unmarshal will populate the interface x
// succesfully and then return an UnmarshalWarning error with the
// remaining bytes.
func Unmarshal(x interface{}, data []byte) error {
	i, err := UnmarshalPartial(x, data)
	if err != nil {
		return err
	}

	if uint(len(data)) != i {
		return UnmarshalWarning(data[i:])
	}

	return nil
}

func newState(data []byte) *state {
	return &state{data, 0}
}

func (s *state) read(v reflect.Value, p properties) error {
	if !v.IsValid() {
		return fmt.Errorf("Invalid value")
	}

	if v.CanAddr() {
		v = v.Addr()
	}
	for {
		if v.Type().NumMethod() > 0 && v.CanInterface() {
			if u, ok := v.Interface().(Unmarshaler); ok {
				n, err := u.UnmarshalC(s.data[s.position:])
				if s.position+n > uint(len(s.data)) {
					return errors.New("Out of bound consumption on UnmarshalC")
				}
				s.position += n
				return err
			}
		}

		if v.CanAddr() && v.Kind() != reflect.Interface {
			break
		}
		v = v.Elem()
	}

	switch v.Kind() {
	case reflect.Uint8:
		return s.readUint(1, v, p)
	case reflect.Uint16:
		return s.readUint(2, v, p)
	case reflect.Uint32:
		return s.readUint(4, v, p)
	case reflect.Struct:
		return s.readStruct(v, p)
	case reflect.Slice:
		return s.readSlice(v, p)
	case reflect.String:
		return s.readString(v, p)
	default:
		return fmt.Errorf("Unsupported type: %v", v.Kind())
	}

}

func (s *state) readUint(size uint, v reflect.Value, p properties) error {
	if s.remain() < size {
		return fmt.Errorf("Stream too short at position %d to read (uint%d)", s.position, size*8)
	}
	var result uint64 = 0
	for i := uint(0); i < size; i++ {
		result |= uint64(s.data[s.position+i]) << ((size - 1 - i) * 8)
	}
	s.position += size

	v.SetUint(result)

	return nil
}

func (s *state) readStruct(v reflect.Value, p properties) error {
	for i := 0; i < v.NumField(); i++ {
		vf := v.Field(i)
		t := v.Type()
		sf := t.Field(i)
		q := p.clone()
		if val, ok := sf.Tag.Lookup("u2"); ok {
			if err := q.append(val); err != nil {
				return err
			}
		}
		if _, ok := q["ignore"]; ok {
			continue
		}
		if err := s.read(vf, q); err != nil {
			return fmt.Errorf("Failed to read field %s.%s.%s: %s", t.PkgPath(), t.Name(), sf.Name, err.Error())
		}
	}
	return nil
}

func (s *state) readSlice(v reflect.Value, p properties) error {
	val, ok := p["slice-length"]
	if !ok {
		return errors.New("attribute slice-length not specified")
	}
	if val == "*" {
		val = "0"
	}
	l, err := strconv.Atoi(val)
	if err != nil {
		return err
	}

	if v.Type().Elem().Kind() == reflect.Uint8 {
		return s.readByteSlice(l, v, p)
	}

	if l < 0 {
		return errors.New("slice-length <0 only supported on byte slices.")
	}

	v.Set(reflect.MakeSlice(v.Type(), l, l))

	for i := 0; i < l; i++ {
		if err := s.read(v.Index(i), p); err != nil {
			return err
		}
	}

	return nil
}

func (s *state) readByteSlice(size int, v reflect.Value, p properties) error {
	if size > 0 {
		if s.remain() < uint(size) {
			return fmt.Errorf("Stream too short at position %d to read byte slice of length %d.", s.position, size)
		}
		v.SetBytes(s.data[s.position : s.position+uint(size)])
		s.position += uint(size)
	} else {
		end := len(s.data) + size
		if end < int(s.position) {
			return fmt.Errorf("Stream too short to at position %d to read dynamic slice ending at %d bytes from end.", s.position, size*-1)
		}
		v.SetBytes(s.data[s.position:end])
		s.position = uint(end)
	}
	return nil
}

func (s *state) readString(v reflect.Value, p properties) error {
	val, ok := p["string-length"]
	if !ok {
		return errors.New("atrribute string-length not specified")
	}
	l, err := strconv.Atoi(val)
	if err != nil {
		return err
	}

	if l < 0 {
		return errors.New("string-length <0 not supported.")
	}

	if s.remain() < uint(l) {
		return fmt.Errorf("Stream too short at position %d to read string of length %d.", s.position, l)
	}

	i := 0
	for ; i < l; i++ {
		if s.data[s.position+uint(i)] == 0x00 {
			break
		}
	}
	v.SetString(string(s.data[s.position : s.position+uint(i)]))
	s.position += uint(l)

	return nil
}
