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

// Package provides entry functions for the parsers in subpackages
package parser

import (
	"fmt"
	"log"

	"github.com/kazkansouh/u2text/parser/classification"
	"github.com/kazkansouh/u2text/parser/gen"
	"github.com/kazkansouh/u2text/parser/protocol"
	"github.com/kazkansouh/u2text/parser/sid"
	"github.com/kazkansouh/u2text/parser/u2"
)

// Synchronously text files that map numeric values into text values
func ParseMaps(sidmap, genmap, clsmap string) (*u2.MessageMap, error) {
	// Start reading all files concurrently
	sid_result, sid_error := sid.ReadFile(sidmap)
	gen_result, gen_error := gen.ReadFile(genmap)
	pro_result, pro_error := protocol.ReadFile()
	cls_result, cls_error := classification.ReadFile(clsmap)
	mmap := u2.MessageMap{}

	select {
	case mmap.S = <-sid_result:
	case err := <-sid_error:
		return nil, fmt.Errorf("Failed to read signature map: %s", err.Error())
	}

	select {
	case mmap.G = <-gen_result:
	case err := <-gen_error:
		return nil, fmt.Errorf("Failed to read generator map: %s", err.Error())
	}

	select {
	case mmap.P = <-pro_result:
	case err := <-pro_error:
		return nil, fmt.Errorf("Failed to read protocol file: %s", err.Error())
	}

	select {
	case mmap.C = <-cls_result:
	case err := <-cls_error:
		return nil, fmt.Errorf("Failed to read classification file: %s", err.Error())
	}

	return &mmap, nil
}

// Parse a given unified2 file asynchronously. Parsed records are
// returned over the channel result.
//
// The channel shutdown is used to stop parsing. If channel is closed,
// parse function will stop immediately (e.g. in case the application
// needs to quit). If unit value is provided, parse will gracefully
// stop at eof (providing eof is at end of a record, otherwise an
// error will occur). The graceful stop can be used when a new spool
// file is detected.
//
// When the parse terminates, the result channel will be closed.
//
// Any errors will be written to the errors channel before process
// terminates. Note, errors is a blocking channel, so result channel
// will only be closed after errors are read from error channel.
func ParseU2(
	file string,
	offset int64,
	shutdown u2.UnitChannel,
) (<-chan *u2.Record, <-chan error) {
	result := make(chan *u2.Record, 0)
	errors := make(chan error, 0)
	log.Printf("Parsing %s at offset %x\n", file, offset)
	go func() {
		defer close(result)
		if err := u2.Parse(file, offset, shutdown, result); err != nil {
			errors <- err
		}

	}()
	return result, errors
}
