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
func readData(f *os.File, b []byte, shutdown UnitChannel, isgraceful bool) readDataResult {
	toread := b[:]
	result := proceed
	if isgraceful {
		result = gracefulShutdown
	}
	for {
		n, err := f.Read(toread)
		if n > 0 {
			toread = toread[n:]
			if len(toread) == 0 {
				return result
			}
		}
		if err != nil && err != io.EOF {
			log.Println("Unable to read from file:", err)
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
// When the parse function terminates, the channel will be closed.
func Parse(file string, offset int64, shutdown UnitChannel, result chan<- *Record) {
	defer func() {
		close(result)
	}()
	log.Printf("Parsing %s at offset %x\n", file, offset)

	f, err := os.OpenFile(file, os.O_RDONLY, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		f.Close()
	}()

	newoffset, err := f.Seek(offset, 0)
	if err != nil {
		log.Fatal(err)
	}
	if offset != newoffset {
		log.Fatal("file location is not what was requested")
	}

	graceful := false
	for {
		buffer := make([]byte, 8)
		switch readData(f, buffer, shutdown, graceful) {
		case proceed:
			offset += int64(len(buffer))
		case failure:
			log.Fatal("unable to read header")
		case shutdownNow:
			return
		case gracefulShutdown:
			graceful = true
		case noRead:
			log.Println("Graceful shutdown at EOF")
			return
		}

		hdr := header{}
		if err := encoding.Unmarshal(&hdr, buffer); err != nil {
			log.Fatal(err)
		}

		buffer = make([]byte, hdr.Length)
		switch readData(f, buffer, shutdown, false) {
		case proceed:
			offset += int64(len(buffer))
		case failure:
			log.Fatal("unable to read data")
		case shutdownNow:
			return
		case gracefulShutdown:
			graceful = true
		case noRead:
			log.Fatal("unexpected eof reached")
		}

		log.Printf("read record of type %d with length %d\n", hdr.Tag, hdr.Length)

		switch hdr.Tag {
		case UNIFIED2_PACKET:
			packet := Unified2Packet{}
			if err := encoding.Unmarshal(&packet, buffer); err != nil {
				log.Fatal(err)
			}
			if packet.Packet_length != uint32(len(packet.Packet_data)) {
				log.Fatal("Packet length does not match expected length")
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
				log.Fatal(err)
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
				log.Fatal(err)
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
				log.Fatal(err)
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
				log.Fatal(err)
			}
			result <- &Record{
				Tag:      hdr.Tag,
				Name:     "IDS Event2 (IPv6)",
				R:        &event,
				FileName: file,
				Offset:   offset,
			}
		default:
			log.Println("WARNING: Ignoring unknown record tag: ", hdr.Tag)
		}
	}
}
