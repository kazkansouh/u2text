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

// Simple parser to read text files that contain entries of the
// format (used by snort message maps):
//
//   # comment line
//   field_1 || .. || field_n
//
// Allows for empty lines and lines the begin with # for comments.
package msg

import (
	"bufio"
	"io"
	"strings"
)

// Line of the file represented as a list of fields
type Line []string

// Wrap up existing bufio reader
type Reader struct {
	reader *bufio.Reader
}

// NewReader wraps bufio reader NewReader
func NewReader(rd io.Reader) *Reader {
	return &Reader{
		reader: bufio.NewReader(rd),
	}
}

// Read structured line to parse next line available into Line
// structure.
//
// Returns slice of fields if line is not empty and not comment,
// otherwise nil is returned (e.g. in the case of eof)
func (r *Reader) ReadNext() (Line, error) {
	for {
		line, err := r.reader.ReadString('\n')
		line = strings.TrimSpace(line)

		if !strings.HasPrefix(line, "#") && line != "" {
			return strings.Split(line, " || "), err
		}

		if err != nil {
			return nil, err
		}
	}
}
