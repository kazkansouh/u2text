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
// Quoting the man page for protocols:
//
//     This file is a plain ASCII file, describing the various DARPA
//     internet protocols that are available from the TCP/IP subsystem.  It
//     should be consulted instead of using the numbers in the ARPA include
//     files, or, even worse, just guessing them.  These numbers will occur
//     in the protocol field of any IP header.
//
//     Keep this file untouched since changes would result in incorrect IP
//     packages.  Protocol numbers and names are specified by the IANA
//     (Internet Assigned Numbers Authority).
//
//     Each line is of the following format:
//
//            protocol number aliases ...
//
//     where the fields are delimited by spaces or tabs.  Empty lines are
//     ignored.  If a line contains a hash mark (#), the hash mark and the
//     part of the line following it are ignored.
//
//     The field descriptions are:
//
//     protocol
//            the native name for the protocol.  For example ip, tcp, or
//            udp.
//
//     number the official number for this protocol as it will appear within
//            the IP header.
//
//     aliases
//            optional aliases for the protocol.
//
//     This file might be distributed over a network using a network-wide
//     naming service like Yellow Pages/NIS or BIND/Hesiod.
package protocol

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
			return strings.Fields(line), err
		}

		if err != nil {
			return nil, err
		}
	}
}

// Reverse map of protocol nubmers to their names
type ProtocolMap map[uint8]string

func readFile(file string, result chan<- ProtocolMap, errors chan<- error) {
	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		errors <- err
		return
	}
	defer func() {
		f.Close()
	}()

	m := ProtocolMap{}
	reader := bufio.NewReader(f)

	for {
		words, err := readNext(reader)
		if err == nil || (err == io.EOF && words != nil) {
			if len(words) >= 2 {
				id, err := strconv.Atoi(words[1])
				if err != nil {
					errors <- fmt.Errorf("Unable to protocol number on line %q: %s", words, err.Error())
					return
				}
				if id < 0 || id >= 256 {
					errors <- fmt.Errorf("Out of range protocol number (%d).", id)
				}
				m[uint8(id)] = words[0]
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

// Asynchronously read /etc/protocols, the result/errors are returned
// over channels. The caller should use a select statement.
func ReadFile() (<-chan ProtocolMap, <-chan error) {
	result := make(chan ProtocolMap, 1)
	errors := make(chan error, 1)
	go readFile("/etc/protocols", result, errors)
	return result, errors
}
