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

// Package sid reads the standard sid-msg.map file that is distributed
// with snort's rule set. A line of this file is of the format:
//   numeric-id || text-description || ref-1 || .. || ref-n
package sid

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/kazkansouh/u2text/parser/msg"
)

// Defines the fields for a signature
type SID struct {
	// Textual description of the signature
	Description string

	// List of associated reference ids, e.g. cve
	References []string
}

// Representation of sid-msg.map file
type SidMap map[uint32]*SID

func readFile(file string, result chan<- SidMap, errors chan<- error) {
	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		errors <- err
		return
	}
	defer func() {
		f.Close()
	}()

	m := SidMap{}
	reader := msg.NewReader(f)

	for {
		fields, err := reader.ReadNext()
		if err == nil || (err == io.EOF && fields != nil) {
			if len(fields) >= 2 {
				id, err := strconv.Atoi(fields[0])
				if err != nil {
					errors <- fmt.Errorf("Unable to parse id on line %s: %s", fields, err.Error())
					return
				}
				if id < 0 {
					errors <- fmt.Errorf("Negative id (%d) is not valid.", id)
				}
				m[uint32(id)] = &SID{
					Description: fields[1],
					References:  fields[2:],
				}
			} else {
				errors <- fmt.Errorf("Incorrect number of fields on line: %s", fields)
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

// Asynchronously read sid-msg.map, the result/errors are returned
// over channels. The caller should use a select statement.
func ReadFile(file string) (<-chan SidMap, <-chan error) {
	result := make(chan SidMap, 1)
	errors := make(chan error, 1)
	go readFile(file, result, errors)
	return result, errors
}
