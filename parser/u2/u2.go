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

// Package parses a single unified2 file asynchronously into
// structures that represent the underlying file. No processing or
// correlation is included here.
//
// The subpackage "encoding" provides the unmarshalling functions.
//
// Code based on u2spewfoo operation (from snort release 2.9.13).
package u2

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/kazkansouh/u2text/parser/u2/encoding"
)

type readDataResult int

const (
	proceed readDataResult = iota
	failure
	shutdownNow
	gracefulShutdown
	noRead
)

// Used for channel communication that has no data
type Unit struct{}
type UnitChannel <-chan *Unit

// Convenience value, used by consumers of the package to write to
// shutdown channel
var U = &Unit{}

// Read requested number of bytes from file
func readData(
	r io.Reader,
	b []byte, shutdown UnitChannel,
	isgraceful bool,
	errors chan<- error,
) readDataResult {
	toread := b[:]
	result := proceed
	if isgraceful {
		result = gracefulShutdown
	}
	for {
		n, err := r.Read(toread)
		if n > 0 {
			toread = toread[n:]
			if len(toread) == 0 {
				return result
			}
		}
		if err != nil && err != io.EOF {
			errors <- err
			return failure
		}
		// eof was received at begining of block
		if n == 0 && err == io.EOF && result == gracefulShutdown {
			return noRead
		}
		// not all data was read, wait a short while and try again
		select {
		case <-time.NewTimer(time.Second).C:
		case _, ok := <-shutdown:
			if !ok {
				// bail out now
				return shutdownNow
			} else {
				// read to end of block
				result = gracefulShutdown
			}
		}
	}
}

type header struct {
	Tag, Length uint32
}

// Parsed record is placed in this structure. Tag defines which type
// of record is stored in R.
type Record struct {
	// This determines they structure stored in R. The value of
	// the tag is directly read from the underlying record.
	Tag uint32

	// Textual representation of tag (mapping defined by program)
	Name string

	// Tag == 2: Unified2Packet
	// Tag == 7: Unified2IDSEvent_legacy
	// Tag == 72: Unified2IDSEventIPv6_legacy
	// Tag == 104: Unified2IDSEvent
	// Tag == 105: Unified2IDSEventIPv6
	R interface{}

	// File that the event was parsed from
	FileName string
	// Current offset (i.e. position after record was read)
	Offset int64
}

// Applies MessageMap m to R, if appropriate
func (r *Record) BondMessageMap(m *MessageMap) {
	if R, ok := r.R.(MessageBonder); ok {
		R.BondMessageMap(m)
	}
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
// terminates.
func Parse(
	file string,
	offset int64,
	shutdown UnitChannel,
	result chan<- *Record,
	errors chan<- error,
) {
	defer func() {
		close(result)
	}()

	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		errors <- err
		return
	}
	defer func() {
		f.Close()
	}()

	newoffset, err := f.Seek(offset, 0)
	if err != nil {
		errors <- err
		return
	}
	if offset != newoffset {
		errors <- fmt.Errorf("Unable to seek to %d", offset)
		return
	}

	graceful := false
	for {
		buffer := make([]byte, 8)
		switch readData(f, buffer, shutdown, graceful, errors) {
		case proceed:
			offset += int64(len(buffer))
		case failure:
			errors <- fmt.Errorf("Unable to read unified2 header from %s", file)
			return
		case shutdownNow:
			return
		case gracefulShutdown:
			graceful = true
		case noRead:
			return
		}

		hdr := header{}
		if err := encoding.Unmarshal(&hdr, buffer); err != nil {
			errors <- err
			return
		}

		buffer = make([]byte, hdr.Length)
		switch readData(f, buffer, shutdown, false, errors) {
		case proceed:
			offset += int64(len(buffer))
		case failure:
			errors <- fmt.Errorf("Unable to read unified2 record data from %s", file)
			return
		case shutdownNow:
			return
		case gracefulShutdown:
			graceful = true
		case noRead:
			errors <- fmt.Errorf("Unexpected eof reached while reading unified2 record at offset: %d", offset)
			return
		}

		switch hdr.Tag {
		case UNIFIED2_PACKET:
			packet := Unified2Packet{}
			if err := encoding.Unmarshal(&packet, buffer); err != nil {
				errors <- err
				return
			}
			if packet.Packet_length != uint32(len(packet.Packet_data)) {
				errors <- fmt.Errorf("Packet length does not match expected length: expected %d, got %d", packet.Packet_length, len(packet.Packet_data))
				return
			}
			packet.packet_data = packet.Packet_data
			result <- &Record{
				Tag:      hdr.Tag,
				Name:     "Packet",
				R:        &packet,
				FileName: file,
				Offset:   offset,
			}
		case UNIFIED2_IDS_EVENT:
			event := Unified2IDSEvent_legacy{}
			if err := encoding.Unmarshal(&event, buffer); err != nil {
				errors <- err
				return
			}
			result <- &Record{
				Tag:      hdr.Tag,
				Name:     "IDS Event (IPv4)",
				R:        &event,
				FileName: file,
				Offset:   offset,
			}
		case UNIFIED2_IDS_EVENT_IPV6:
			event := Unified2IDSEventIPv6_legacy{}
			if err := encoding.Unmarshal(&event, buffer); err != nil {
				errors <- err
				return
			}
			result <- &Record{
				Tag:      hdr.Tag,
				Name:     "IDS Event (IPv6)",
				R:        &event,
				FileName: file,
				Offset:   offset,
			}
		case UNIFIED2_IDS_EVENT_VLAN:
			event := Unified2IDSEvent{}
			if err := encoding.Unmarshal(&event, buffer); err != nil {
				errors <- err
				return
			}
			result <- &Record{
				Tag:      hdr.Tag,
				Name:     "IDS Event2 (IPv4)",
				R:        &event,
				FileName: file,
				Offset:   offset,
			}
		case UNIFIED2_IDS_EVENT_IPV6_VLAN:
			event := Unified2IDSEventIPv6{}
			if err := encoding.Unmarshal(&event, buffer); err != nil {
				errors <- err
				return
			}
			result <- &Record{
				Tag:      hdr.Tag,
				Name:     "IDS Event2 (IPv6)",
				R:        &event,
				FileName: file,
				Offset:   offset,
			}
		default:
			// TODO: support UNIFIED2_EXTRA_DATA
			log.Println("WARNING: Ignoring unknown record tag: ", hdr.Tag)
		}
	}
}
