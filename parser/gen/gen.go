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

// Package gen reads the standard gen-msg.map file that is distributed
// with snort. A line of this file is of the format:
//   generator-id || alert-id || text-description
package gen

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/kazkansouh/u2text/parser/msg"
)

// Defines the fields for a generator
type GEN struct {
	// Textual description of generator
	Description string
}

// Representation of gen-msg.map file
type GenMap map[uint32]map[uint32]*GEN

func readFile(file string, result chan<- GenMap, errors chan<- error) {
	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		errors <- err
		return
	}
	defer func() {
		f.Close()
	}()

	m := GenMap{}
	reader := msg.NewReader(f)

	for {
		fields, err := reader.ReadNext()
		if err == nil || (err == io.EOF && fields != nil) {
			if len(fields) == 3 {
				genid, err := strconv.Atoi(fields[0])
				if err != nil {
					errors <- fmt.Errorf("Unable to parse generator id on line %s: %s", fields, err.Error())
					return
				}
				if genid < 0 {
					errors <- fmt.Errorf("Negative generator id (%d) is not valid.", genid)
				}
				alertid, err := strconv.Atoi(fields[1])
				if err != nil {
					errors <- fmt.Errorf("Unable to parse alert id on line %s: %s", fields, err.Error())
					return
				}
				if alertid < 0 {
					errors <- fmt.Errorf("Negative alert id (%d) is not valid.", alertid)
				}

				_, ok := m[uint32(genid)]
				if !ok {
					m[uint32(genid)] = map[uint32]*GEN{}
				}
				m[uint32(genid)][uint32(alertid)] = &GEN{
					Description: fields[2],
				}
			} else {
				errors <- fmt.Errorf("Incorrect number of fields on line: %#v", fields)
				return
			}
		}
		if err != nil && err != io.EOF {
			errors <- err
			return
		}
		if err == io.EOF {
			break
		}
	}
	result <- m
}

// Asynchronously read gen-msg.map, the result/errors are returned
// over channels. The caller should use a select statement.
func ReadFile(file string) (<-chan GenMap, <-chan error) {
	result := make(chan GenMap, 1)
	errors := make(chan error, 1)
	go readFile(file, result, errors)
	return result, errors
}
