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

// Package protocol reads the /etc/protocol file and builds up a
// map[uint8]string. uint8 is used as that is what is present in the
// unified2 records.
//
// Entries of the classification file are of the format:
//
//   # comments are ok
//   config classification:shortname,short description,priority
package classification

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Read a line of text into a list of words, ignoring empty liens and
// comments.
func readNext(r *bufio.Reader) ([]string, error) {
	for {
		line, err := r.ReadString('\n')
		line = strings.SplitN(line, "#", 2)[0]
		line = strings.TrimSpace(line)

		if line != "" {
			if configLine := strings.SplitN(line, ":", 2); len(configLine) == 2 {
				directive := strings.Fields(configLine[0])
				if directive[0] == "config" && directive[1] == "classification" {
					fields := strings.Split(configLine[1], ",")
					for i, f := range fields {
						fields[i] = strings.TrimSpace(f)
					}
					return fields, nil
				} else {
					if err != nil {
						return nil, err
					}
					continue
				}
			}
			return nil, fmt.Errorf("Unexpected line read: %q", line)
		}

		if err != nil {
			return nil, err
		}
	}
}

// Representation of a line in the config file
type Classification struct {
	Name        string
	Description string
	Priority    uint32
}

// Map of classifications into their meanings. The key is taken from
// the position in the file.
type ClassMap map[uint32]*Classification

func readFile(file string, result chan<- ClassMap, errors chan<- error) {
	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		errors <- err
		return
	}
	defer func() {
		f.Close()
	}()

	m := ClassMap{}
	reader := bufio.NewReader(f)
	index := uint32(1)

	for {
		words, err := readNext(reader)
		if err == nil || (err == io.EOF && words != nil) {
			if len(words) == 3 {
				priority, err := strconv.Atoi(words[2])
				if err != nil {
					errors <- fmt.Errorf("Unable to parse priority on line %q: %s", words, err.Error())
					return
				}
				if priority < 0 {
					errors <- fmt.Errorf("Out of range priority (%d).", priority)
				}
				m[index] = &Classification{
					Name:        words[0],
					Description: words[1],
					Priority:    uint32(priority),
				}
				index++
			} else {
				errors <- fmt.Errorf("Incorrect number of words on line: %q", words)
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

// Asynchronously read classification file, the result/errors are
// returned over channels. The caller should use a select statement.
func ReadFile(file string) (<-chan ClassMap, <-chan error) {
	result := make(chan ClassMap, 1)
	errors := make(chan error, 1)
	go readFile(file, result, errors)
	return result, errors
}
