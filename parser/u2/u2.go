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
	b []byte,
	shutdown UnitChannel,
	isgraceful bool,
	noop bool,
) (readDataResult, error) {
	toread := b[:]
	result := proceed
	if isgraceful {
		result = gracefulShutdown
	}
	// first, perform a nonblocking check to see if a
	// shutdown is requested
	select {
	case _, ok := <-shutdown:
		if !ok {
			// bail out now
			return shutdownNow, nil
		}
		// read to end of block
		result = gracefulShutdown
	default:
	}
	for {
		// read the data
		n, err := r.Read(toread)
		if n > 0 {
			toread = toread[n:]
			if len(toread) == 0 {
				return result, nil
			}
		}
		if err != nil && err != io.EOF {
			return failure, err
		}
		// eof was received at begining of block
		if n == 0 && err == io.EOF && result == gracefulShutdown && noop {
			return noRead, nil
		}
		// not all data was read, wait a short while and try again
		select {
		case <-time.NewTimer(time.Millisecond * 100).C:
		case _, ok := <-shutdown:
			if !ok {
				// bail out now
				return shutdownNow, nil
			}
			// read to end of block
			result = gracefulShutdown
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

// Stubbing a read only interface of a file
type readSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
	Stat() (os.FileInfo, error)
}

var (
	// stubbed os.OpenFile for testing
	openFile = func(file string, flag int, perms os.FileMode) (readSeekCloser, error) {
		return os.OpenFile(file, flag, perms)
	}
)

// Error codes produced by Parse function
type ErrorCode int

// Sequence of error constants produced by Parse function
const (
	// Unable to open file
	E_Open ErrorCode = iota
	// When Seek returns an error or when Seek reports no error
	// but did not seek to expected location
	E_Seek
	// When an occurs from during reading data from file,
	// typically during a Read operation
	E_ReadData
	// Incorrect format of data read from file
	E_Unmarshal
	// Length of Unified2Packet does not match length in
	// header. Possible corrupt file.
	E_PacketLen
	// Reading information about file failed, i.e. calling
	// os.File.Stat
	E_FileInfo
)

// Errors returned by parse function, type primarily used for test
// code
type ParseError interface {
	error
	File() string
	Code() ErrorCode
	NextError() error
}

type parseError struct {
	message string
	file    string
	ErrorCode
	error
}

func (e *parseError) Error() string {
	msg := e.file
	if e.message != "" {
		msg = msg + ": " + e.message
	}
	if e.error != nil {
		msg = msg + ": " + e.error.Error()
	}
	return msg
}

func (e *parseError) File() string {
	return e.file
}

func (e *parseError) Code() ErrorCode {
	return e.ErrorCode
}

func (e *parseError) NextError() error {
	return e.error
}

// Parse a given unified2 file asynchronously. Parsed records are
// returned over the channel result. Only the below types are parsed,
// any other type will have the unprocessed byte slice returned in the
// record.
//
//   UNIFIED2_PACKET uint32 = 2
//   UNIFIED2_IDS_EVENT uint32 = 7
//   UNIFIED2_IDS_EVENT_IPV6 uint32 = 72
//   UNIFIED2_IDS_EVENT_VLAN uint32 = 104
//   UNIFIED2_IDS_EVENT_IPV6_VLAN uint32 = 105
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
) error {
	f, err := openFile(file, os.O_RDONLY, 0)
	if err != nil {
		return &parseError{
			message:   "Unable to open file",
			file:      file,
			ErrorCode: E_Open,
			error:     err,
		}
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return &parseError{
			message:   "Unable to read file info",
			file:      file,
			ErrorCode: E_FileInfo,
			error:     err,
		}
	}

	if fi.Size() < offset {
		return &parseError{
			message:   "Offset larger than file",
			file:      file,
			ErrorCode: E_Seek,
			error:     err,
		}
	}

	newoffset, err := f.Seek(offset, io.SeekStart)
	if err != nil {
		return &parseError{
			message:   "Unable to seek on file",
			file:      file,
			ErrorCode: E_Seek,
			error:     err,
		}
	}
	if offset != newoffset {
		// maybe this is not a valid situation
		return &parseError{
			message:   "Seek to wrong location",
			file:      file,
			ErrorCode: E_Seek,
		}
	}

	graceful := false
	for {
		buffer := make([]byte, 8)
		switch r, err := readData(f, buffer, shutdown, graceful, true); r {
		case proceed:
			offset += int64(len(buffer))
		case failure:
			return &parseError{
				message:   "Unable to read unified2 header",
				file:      file,
				ErrorCode: E_ReadData,
				error:     err,
			}
		case shutdownNow:
			return nil
		case gracefulShutdown:
			offset += int64(len(buffer))
			graceful = true
		case noRead:
			return nil
		}

		// not possible to generate error when unmarshalling
		// as header consists of 2 uint32, i.e. any 8 bytes
		// are valid
		hdr := header{}
		encoding.Unmarshal(&hdr, buffer)

		buffer = make([]byte, hdr.Length)
		switch r, err := readData(f, buffer, shutdown, false, false); r {
		case proceed:
			offset += int64(len(buffer))
		case failure:
			return &parseError{
				message:   "Unable to read unified2 record data",
				file:      file,
				ErrorCode: E_ReadData,
				error:     err,
			}
		case shutdownNow:
			return nil
		case gracefulShutdown:
			offset += int64(len(buffer))
			graceful = true
		}

		switch hdr.Tag {
		case UNIFIED2_PACKET:
			packet := Unified2Packet{}
			if err := encoding.Unmarshal(&packet, buffer); err != nil {
				return &parseError{
					file:      file,
					ErrorCode: E_Unmarshal,
					error:     err,
				}
			}
			if packet.Packet_length != uint32(len(packet.Packet_data)) {
				return &parseError{
					message:   fmt.Sprintf("Packet length does not match expected length: expected %d, got %d", packet.Packet_length, len(packet.Packet_data)),
					file:      file,
					ErrorCode: E_PacketLen,
				}
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
				return &parseError{
					file:      file,
					ErrorCode: E_Unmarshal,
					error:     err,
				}
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
				return &parseError{
					file:      file,
					ErrorCode: E_Unmarshal,
					error:     err,
				}
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
				return &parseError{
					file:      file,
					ErrorCode: E_Unmarshal,
					error:     err,
				}
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
				return &parseError{
					file:      file,
					ErrorCode: E_Unmarshal,
					error:     err,
				}
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
			result <- &Record{
				Tag:      hdr.Tag,
				Name:     "Unknown",
				R:        buffer,
				FileName: file,
				Offset:   offset,
			}
		}
	}
}
