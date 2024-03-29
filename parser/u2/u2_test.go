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

package u2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"

	"gotest.tools/assert"

	"github.com/kazkansouh/gotestlib/testio"
)

var (
	anError    = errors.New("An Error")
	otherError = errors.New("A Different Error")
)

func TestReadData(t *testing.T) {
	type test struct {
		name          string
		source        []byte
		reader        func(shutdown chan<- *Unit, source []byte) io.Reader
		readlen       int
		graceful      bool
		noop          bool
		expected      readDataResult
		error         string
		checkshutdown bool
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			buffer := make([]byte, test.readlen)
			shutdown := make(chan *Unit, 1)

			result, err := readData(
				test.reader(shutdown, test.source),
				buffer,
				shutdown,
				test.graceful,
				test.noop,
			)

			assert.Equal(t, result, test.expected)

			if result == proceed || result == gracefulShutdown {
				assert.Assert(t, test.readlen <= len(test.source))
				assert.DeepEqual(t, buffer, test.source[:test.readlen])
			}

			if test.error != "" {
				assert.ErrorContains(t, err, test.error)
			} else {
				assert.NilError(t, err)
			}

			if test.checkshutdown {
				t.Log("checking if shutdown queue is empty")
				select {
				case _, ok := <-shutdown:
					assert.Assert(t, !ok)
				default:
				}
			}
		}
	}

	for _, test := range []*test{
		&test{
			name:          "progress",
			source:        []byte("Hello World!"),
			reader:        func(sh chan<- *Unit, src []byte) io.Reader { return bytes.NewReader(src) },
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      proceed,
			error:         "",
			checkshutdown: false,
		},
		&test{
			name:   "failure",
			source: []byte("Hello World!"),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				return testio.NewHookedReader(
					bytes.NewBuffer(src),
					5,
					func(ctr int) (next int, err error) {
						return -1, anError
					},
				)
			},
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      failure,
			error:         anError.Error(),
			checkshutdown: false,
		},
		&test{
			name:   "brutal-start",
			source: []byte("Hello World!"),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				close(sh)
				return bytes.NewReader(src)
			},
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      shutdownNow,
			error:         "",
			checkshutdown: false,
		},
		&test{
			name:   "brutal-mid",
			source: []byte("Hello World!"),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				return testio.NewHookedReader(
					bytes.NewBuffer(src),
					2,
					func(ctr int) (next int, err error) {
						close(sh)
						return -1, io.EOF
					},
				)
			},
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      shutdownNow,
			error:         "",
			checkshutdown: false,
		},
		&test{
			name:   "graceful-start-brutal-mid",
			source: []byte("Hello World!"),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				return testio.NewHookedReader(
					bytes.NewBuffer(src),
					2,
					func(ctr int) (next int, err error) {
						if next == 1 {
							sh <- U
							return 2, io.EOF
						} else {
							close(sh)
							return -1, io.EOF
						}
					},
				)
			},
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      shutdownNow,
			error:         "",
			checkshutdown: true,
		},
		&test{
			name:   "graceful-start",
			source: []byte("Hello World!"),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				sh <- U
				return bytes.NewReader(src)
			},
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      gracefulShutdown,
			error:         "",
			checkshutdown: false,
		},
		&test{
			name:   "graceful-mid",
			source: []byte("Hello World!"),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				return testio.NewHookedReader(
					bytes.NewBuffer(src),
					2,
					func(ctr int) (next int, err error) {
						sh <- U
						return -1, io.EOF
					},
				)
			},
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      gracefulShutdown,
			error:         "",
			checkshutdown: true,
		},
		&test{
			name:          "graceful-initial",
			source:        []byte("Hello World!"),
			reader:        func(sh chan<- *Unit, src []byte) io.Reader { return bytes.NewReader(src) },
			readlen:       10,
			graceful:      true,
			noop:          true,
			expected:      gracefulShutdown,
			error:         "",
			checkshutdown: false,
		},
		&test{
			name:   "graceful-with-op",
			source: []byte(""),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				itr := 0
				return testio.RF(func(p []byte) (int, error) {
					// perform 2 reads then fail
					if itr == 2 {
						return 0, anError
					}
					itr += 1
					return 0, io.EOF
				})
			},
			readlen:       10,
			graceful:      true,
			noop:          false,
			expected:      failure,
			error:         anError.Error(),
			checkshutdown: false,
		},
		&test{
			name:   "graceful-initial-with-noop",
			source: []byte(""),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				itr := 0
				return testio.RF(func(p []byte) (int, error) {
					// perform 2 reads then fail
					if itr == 2 {
						return 0, anError
					}
					itr += 1
					return 0, io.EOF
				})
			},
			readlen:       10,
			graceful:      true,
			noop:          true,
			expected:      noRead,
			error:         "",
			checkshutdown: false,
		},
		&test{
			name:   "graceful-mid-with-noop",
			source: []byte(""),
			reader: func(sh chan<- *Unit, src []byte) io.Reader {
				itr := 0
				return testio.RF(func(p []byte) (int, error) {
					if itr == 0 {
						sh <- U
					}
					// perform 2 reads then fail
					if itr == 2 {
						return 0, anError
					}
					itr += 1
					return 0, io.EOF
				})
			},
			readlen:       10,
			graceful:      false,
			noop:          true,
			expected:      noRead,
			error:         "",
			checkshutdown: true,
		},
	} {
		t.Run(test.name, testfunc(test))
	}
}

type bondable struct {
	C chan *MessageMap
}

func (r *bondable) BondMessageMap(m *MessageMap) {
	r.C <- m
}

// case where R implements MessageBonder
func TestRecordMessageBonder(t *testing.T) {
	b := bondable{make(chan *MessageMap, 1)}
	r := Record{R: &b}
	m := &MessageMap{}
	r.BondMessageMap(m)

	select {
	case x := <-b.C:
		if x != m {
			t.Fatal("Unexpected message map retured.")
		}
	default:
		t.Fatal("BondMessageMap was not called on R")
	}
}

func TestParse_NoOpen(t *testing.T) {
	testfunc := func(rsc readSeekCloser) func(*testing.T) {
		return func(t *testing.T) {
			file := "somefile"
			offset := int64(123)
			shutdown := make(UnitChannel, 1)
			results := make(chan *Record, 10)

			defer func(x func(file string, flag int, perms os.FileMode) (readSeekCloser, error)) {
				openFile = x
			}(openFile)
			openFile = func(f string, flag int, p os.FileMode) (readSeekCloser, error) {
				if f != file {
					t.Errorf("incorrect file opened. expecting %s, got %s", file, f)
				}
				if flag&os.O_RDONLY != os.O_RDONLY {
					t.Error("RDONLY flag not set")
				}
				return &testio.MockFile{
					R: rsc,
					S: rsc,
					C: testio.CF(func() error {
						t.Error("Close called on error file")
						return nil
					}),
				}, anError
			}

			errors := make(chan error, 0)
			go func() {
				errors <- Parse(file, offset, shutdown, results)
			}()

			// wait for Parse to terminate
			for results != nil {
				select {
				case err := <-errors:
					results = nil
					pe, ok := err.(ParseError)
					if ok && pe.Code() == E_Open {
						if e := pe.NextError(); e != anError {
							t.Error("Unexpected NextError:", e)
						}
					} else {
						t.Error("ParseError expected")
					}
				case <-results:
					t.Fatal("Parse returned an unexpected result")
				case <-time.NewTimer(time.Millisecond * 100).C:
					t.Fatal("Timeout")

				}
			}
		}
	}
	t.Run("nil file", testfunc(nil))
	t.Run("non-nil file", testfunc(&testio.MockFile{}))
}

func TestParse_NoSeek(t *testing.T) {
	testfunc := func(rsc readSeekCloser, code ErrorCode, expected error) func(*testing.T) {
		return func(t *testing.T) {
			file := "somefile"
			offset := int64(123)
			shutdown := make(UnitChannel, 1)
			results := make(chan *Record, 10)
			closed := make(chan *Unit, 0)

			defer func(x func(file string, flag int, perms os.FileMode) (readSeekCloser, error)) {
				openFile = x
			}(openFile)
			openFile = func(f string, flag int, p os.FileMode) (readSeekCloser, error) {
				return &testio.MockFile{
					S: testio.SF(func(o int64, w int) (int64, error) {
						if w != io.SeekStart {
							t.Error("Seek called without whence=SeekStart")
						}
						if o != offset {
							t.Errorf("Seek called with incorrect offset, expecting %d, got %d", offset, o)
						}
						return rsc.Seek(o, w)
					}),
					C: testio.CF(func() error {
						close(closed)
						return nil
					}),
					St: testio.StatF(rsc.Stat),
				}, nil
			}

			errors := make(chan error, 0)
			go func() {
				errors <- Parse(file, offset, shutdown, results)
			}()

			// wait for Parse to terminate
			for results != nil {
				select {
				case err := <-errors:
					results = nil
					pe, ok := err.(ParseError)
					assert.Assert(t, ok)
					assert.Equal(t, pe.Code(), code)
					assert.Equal(t, pe.File(), file)
					assert.Equal(t, pe.NextError(), expected)
				case <-results:
					t.Fatal("Parse returned an unexpected result")
				case <-time.NewTimer(time.Millisecond * 100).C:
					t.Fatal("Timeout")

				}
			}

			select {
			case <-closed:
			case <-time.NewTimer(time.Millisecond * 100).C:
				t.Error("Timeout")
			}
		}
	}

	t.Run("stat-fail", testfunc(&testio.MockFile{
		St: testio.StatF(func() (os.FileInfo, error) {
			return nil, anError
		}),
	}, E_FileInfo, anError))
	t.Run("out-of-range", testfunc(&testio.MockFile{
		St: testio.StatF(func() (os.FileInfo, error) {
			return &testio.MockFileInfo{FileSize: 100}, nil
		}),
	}, E_Seek, nil))
	t.Run("seeker-error", testfunc(&testio.MockFile{
		St: testio.StatF(func() (os.FileInfo, error) {
			return &testio.MockFileInfo{FileSize: 200}, nil
		}),
		S: testio.SF(func(o int64, w int) (int64, error) {
			return 0, otherError
		}),
	}, E_Seek, otherError))
	t.Run("seeker-wrong-location", testfunc(&testio.MockFile{
		St: testio.StatF(func() (os.FileInfo, error) {
			return &testio.MockFileInfo{FileSize: 200}, nil
		}),
		S: testio.SF(func(o int64, w int) (int64, error) {
			return 0, nil
		}),
	}, E_Seek, nil))

}

func TestParse_Reader(t *testing.T) {
	testfunc := func(
		r func(chan<- *Unit) io.Reader,
		expectedE func(t *testing.T, pe ParseError),
		expectedR func(t *testing.T, i int, r *Record) bool,
		realFile string,
	) func(*testing.T) {
		return func(t *testing.T) {
			offset := int64(0)
			shutdown := make(chan *Unit, 1)
			results := make(chan *Record, 0)
			closed := make(chan *Unit, 0)
			file := "somefile"

			if realFile == "" {
				if testing.Verbose() {
					t.Log("Mocking file")
				}
				defer func(x func(file string, flag int, perms os.FileMode) (readSeekCloser, error)) {
					openFile = x
				}(openFile)
				openFile = func(f string, flag int, p os.FileMode) (readSeekCloser, error) {
					return &testio.MockFile{
						R: r(shutdown),
						C: testio.CF(func() error {
							close(closed)
							return nil
						}),
					}, nil
				}
			} else {
				file = realFile
				shutdown <- U
			}

			errors := make(chan error, 0)
			go func() {
				errors <- Parse(file, offset, shutdown, results)
				// in case a real file was used, close
				// channel here as above close will
				// not be called
				if realFile != "" {
					close(closed)
				}
			}()

			result_ctr := 0
			// wait for Parse to terminate
			for results != nil {
				select {
				case err := <-errors:
					results = nil
					pe, ok := err.(ParseError)
					switch {
					case expectedE == nil && err == nil:
					case expectedE == nil && err != nil:
						t.Error("Unexpected Error:", err)
					case ok:
						if pe.File() != file {
							t.Error("Error for wrong file")
						}
						expectedE(t, pe)
					default:
						t.Error("ParseError expected, got:", err)
					}
				case r := <-results:
					result_ctr++
					if expectedR == nil {
						t.Fatal("Parse returned an unexpected result")
					} else {
						if expectedR(t, result_ctr, r) {
							expectedR = nil
						}
					}
				case <-time.NewTimer(time.Millisecond * 100).C:
					t.Fatal("Timeout")

				}
			}

			if expectedR != nil {
				t.Error("Was expecting a result, but did not get one")
			}

			select {
			case <-closed:
			case <-time.NewTimer(time.Millisecond * 100).C:
				t.Error("Timeout")
			}
		}
	}
	t.Run("fail hdr", testfunc(
		func(s chan<- *Unit) io.Reader {
			return testio.NewHookedReader(
				bytes.NewBuffer([]byte("Hello World!")),
				2,
				func(ctr int) (next int, err error) {
					return -1, anError
				},
			)
		},
		func(t *testing.T, pe ParseError) {
			if pe.Code() != E_ReadData {
				t.Error("Unexpected error code:", pe.Code())
			}
			if pe.NextError() != anError {
				t.Error("Next error is: ", pe.NextError(), " expected to be:", anError)
			}
		},
		nil,
		"",
	))
	t.Run("shutdown hdr", testfunc(
		func(s chan<- *Unit) io.Reader {
			return testio.NewHookedReader(
				bytes.NewBuffer([]byte("Hello World!")),
				2,
				func(ctr int) (next int, err error) {
					if ctr == 1 {
						close(s)
					}
					return 2, nil
				},
			)
		},
		nil,
		nil,
		"",
	))
	t.Run("noread hdr", testfunc(
		func(s chan<- *Unit) io.Reader {
			return testio.NewHookedReader(
				bytes.NewBuffer([]byte("")),
				0,
				func(ctr int) (next int, err error) {
					if ctr == 1 {
						s <- U
					}
					return 2, io.EOF
				},
			)
		},
		nil,
		nil,
		"",
	))
	t.Run("fail body", testfunc(
		func(s chan<- *Unit) io.Reader {
			return testio.NewHookedReader(
				bytes.NewBuffer([]byte{
					0x00, 0x00, 0x00, 0x00, // tag
					0x00, 0x00, 0x00, 0x02, // len
					0x00, 0x00, // body
				}),
				9,
				func(ctr int) (next int, err error) {
					return -1, anError
				},
			)
		},
		func(t *testing.T, pe ParseError) {
			if pe.Code() != E_ReadData {
				t.Error("Unexpected error code:", pe.Code())
			}
			if pe.NextError() != anError {
				t.Error("Next error is: ", pe.NextError(), " expected to be:", anError)
			}
		},
		nil,
		"",
	))
	t.Run("shutdown body", testfunc(
		func(s chan<- *Unit) io.Reader {
			return testio.NewHookedReader(
				bytes.NewBuffer([]byte{
					0x00, 0x00, 0x00, 0x00, // tag
					0x00, 0x00, 0x00, 0x02, // len
					0x00, 0x00, // body
				}),
				9,
				func(ctr int) (next int, err error) {
					if ctr == 1 {
						close(s)
					}
					return 2, nil
				},
			)
		},
		nil,
		nil,
		"",
	))
	t.Run("unmarshal packet", testfunc(
		func(s chan<- *Unit) io.Reader {
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x02, // tag
				0x00, 0x00, 0x00, 0x02, // len
				0x00, 0x00, // body
			})
		},
		func(t *testing.T, pe ParseError) {
			if pe.Code() != E_Unmarshal {
				t.Error("Unexpected error code:", pe.Code())
			}
		},
		nil,
		"",
	))
	t.Run("inconsistent packet len", testfunc(
		func(s chan<- *Unit) io.Reader {
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x02, // tag
				0x00, 0x00, 0x00, 0x20, // len
				0x00, 0x00, 0x00, 0x00, // Sensor_id
				0x00, 0x00, 0x00, 0x00, // Event_id
				0x00, 0x00, 0x00, 0x00, // Event_second
				0x00, 0x00, 0x00, 0x00, // Packet_second
				0x00, 0x00, 0x00, 0x00, // Packet_microsecond
				0x00, 0x00, 0x00, 0x00, // Linktype
				0x00, 0x00, 0x00, 0x05, // Packet_length
				0x00, 0x01, 0x02, 0x03, // Packet_data
			})
		},
		func(t *testing.T, pe ParseError) {
			if pe.Code() != E_PacketLen {
				t.Error("Unexpected error code:", pe.Code())
			}
		},
		nil,
		"",
	))
	for _, v := range []byte{
		byte(UNIFIED2_IDS_EVENT),
		byte(UNIFIED2_IDS_EVENT_IPV6),
		byte(UNIFIED2_IDS_EVENT_VLAN),
		byte(UNIFIED2_IDS_EVENT_IPV6_VLAN),
	} {
		t.Run(fmt.Sprintf("unmarshal event %d", v), testfunc(
			func(s chan<- *Unit) io.Reader {
				return bytes.NewBuffer([]byte{
					0x00, 0x00, 0x00, v, // tag
					0x00, 0x00, 0x00, 0x04, // len
					0x00, 0x00, 0x00, 0x00, // data
				})
			},
			func(t *testing.T, pe ParseError) {
				if pe.Code() != E_Unmarshal {
					t.Error("Unexpected error code:", pe.Code())
				}
			},
			nil,
			"",
		))
	}
	t.Run("packet ok", testfunc(
		func(s chan<- *Unit) io.Reader {
			s <- U
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x02, // tag
				0x00, 0x00, 0x00, 0x20, // len
				0x00, 0x00, 0x00, 0x00, // Sensor_id
				0x00, 0x00, 0x00, 0x00, // Event_id
				0x00, 0x00, 0x00, 0x00, // Event_second
				0x00, 0x00, 0x00, 0x00, // Packet_second
				0x00, 0x00, 0x00, 0x00, // Packet_microsecond
				0x00, 0x00, 0x00, 0x00, // Linktype
				0x00, 0x00, 0x00, 0x04, // Packet_length
				0x00, 0x01, 0x02, 0x03, // Packet_data
			})
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_PACKET {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.(*Unified2Packet); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("legacy event ok", testfunc(
		func(s chan<- *Unit) io.Reader {
			s <- U
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x07, // tag
				0x00, 0x00, 0x00, 0x34, // len
				0x00, 0x00, 0x00, 0x00, // sensor_id
				0x00, 0x00, 0x00, 0x00, // event_id
				0x00, 0x00, 0x00, 0x00, // event_second
				0x00, 0x00, 0x00, 0x00, // event_microsecond
				0x00, 0x00, 0x00, 0x00, // signature_id
				0x00, 0x00, 0x00, 0x00, // generator_id
				0x00, 0x00, 0x00, 0x00, // signature_revision
				0x00, 0x00, 0x00, 0x00, // classification_id
				0x00, 0x00, 0x00, 0x00, // priority_id
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, // sport_itype
				0x00, 0x00, // dport_icode
				0x00, // protocol
				0x00, // impact_flag
				0x00, // impact
				0x00, // blocked
			})
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_IDS_EVENT {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.(*Unified2IDSEvent_legacy); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("legacy ipv6 event ok", testfunc(
		func(s chan<- *Unit) io.Reader {
			s <- U
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x48, // tag
				0x00, 0x00, 0x00, 0x4c, // len
				0x00, 0x00, 0x00, 0x00, // sensor_id
				0x00, 0x00, 0x00, 0x00, // event_id
				0x00, 0x00, 0x00, 0x00, // event_second
				0x00, 0x00, 0x00, 0x00, // event_microsecond
				0x00, 0x00, 0x00, 0x00, // signature_id
				0x00, 0x00, 0x00, 0x00, // generator_id
				0x00, 0x00, 0x00, 0x00, // signature_revision
				0x00, 0x00, 0x00, 0x00, // classification_id
				0x00, 0x00, 0x00, 0x00, // priority_id
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, // sport_itype
				0x00, 0x00, // dport_icode
				0x00, // protocol
				0x00, // impact_flag
				0x00, // impact
				0x00, // blocked
			})
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_IDS_EVENT_IPV6 {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.(*Unified2IDSEventIPv6_legacy); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("event ok", testfunc(
		func(s chan<- *Unit) io.Reader {
			s <- U
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x68, // tag
				0x00, 0x00, 0x00, 0x3c, // len
				0x00, 0x00, 0x00, 0x00, // sensor_id
				0x00, 0x00, 0x00, 0x00, // event_id
				0x00, 0x00, 0x00, 0x00, // event_second
				0x00, 0x00, 0x00, 0x00, // event_microsecond
				0x00, 0x00, 0x00, 0x00, // signature_id
				0x00, 0x00, 0x00, 0x00, // generator_id
				0x00, 0x00, 0x00, 0x00, // signature_revision
				0x00, 0x00, 0x00, 0x00, // classification_id
				0x00, 0x00, 0x00, 0x00, // priority_id
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, // sport_itype
				0x00, 0x00, // dport_icode
				0x00,                   // protocol
				0x00,                   // impact_flag
				0x00,                   // impact
				0x00,                   // blocked
				0x00, 0x00, 0x00, 0x00, // mpls_label
				0x00, 0x00, // vlanId
				0x00, 0x00, // Policy ID
			})
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_IDS_EVENT_VLAN {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.(*Unified2IDSEvent); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("ipv6 event ok", testfunc(
		func(s chan<- *Unit) io.Reader {
			s <- U
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x69, // tag
				0x00, 0x00, 0x00, 0x54, // len
				0x00, 0x00, 0x00, 0x00, // sensor_id
				0x00, 0x00, 0x00, 0x00, // event_id
				0x00, 0x00, 0x00, 0x00, // event_second
				0x00, 0x00, 0x00, 0x00, // event_microsecond
				0x00, 0x00, 0x00, 0x00, // signature_id
				0x00, 0x00, 0x00, 0x00, // generator_id
				0x00, 0x00, 0x00, 0x00, // signature_revision
				0x00, 0x00, 0x00, 0x00, // classification_id
				0x00, 0x00, 0x00, 0x00, // priority_id
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_source
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, 0x00, 0x00, // ip_destination
				0x00, 0x00, // sport_itype
				0x00, 0x00, // dport_icode
				0x00,                   // protocol
				0x00,                   // impact_flag
				0x00,                   // impact
				0x00,                   // blocked
				0x00, 0x00, 0x00, 0x00, // mpls_label
				0x00, 0x00, // vlanId
				0x00, 0x00, // Policy ID
			})
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_IDS_EVENT_IPV6_VLAN {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.(*Unified2IDSEventIPv6); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("extra data - non processed", testfunc(
		func(s chan<- *Unit) io.Reader {
			s <- U
			return bytes.NewBuffer([]byte{
				0x00, 0x00, 0x00, 0x6e, // tag
				0x00, 0x00, 0x00, 0x01, // len
				0x00, // data
			})
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_EXTRA_DATA {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.([]byte); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("graceful hdr", testfunc(
		func(s chan<- *Unit) io.Reader {
			return testio.NewHookedReader(
				bytes.NewBuffer([]byte{
					0x00, 0x00, 0x00, 0x02, // tag
					0x00, 0x00, 0x00, 0x20, // len
					0x00, 0x00, 0x00, 0x00, // Sensor_id
					0x00, 0x00, 0x00, 0x00, // Event_id
					0x00, 0x00, 0x00, 0x00, // Event_second
					0x00, 0x00, 0x00, 0x00, // Packet_second
					0x00, 0x00, 0x00, 0x00, // Packet_microsecond
					0x00, 0x00, 0x00, 0x00, // Linktype
					0x00, 0x00, 0x00, 0x04, // Packet_length
					0x00, 0x01, 0x02, 0x03, // Packet_data
				}),
				4,
				func(ctr int) (next int, err error) {
					if ctr == 1 {
						s <- U
					}
					return 100, nil
				},
			)
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_PACKET {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.(*Unified2Packet); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("graceful body", testfunc(
		func(s chan<- *Unit) io.Reader {
			return testio.NewHookedReader(
				bytes.NewBuffer([]byte{
					0x00, 0x00, 0x00, 0x02, // tag
					0x00, 0x00, 0x00, 0x20, // len
					0x00, 0x00, 0x00, 0x00, // Sensor_id
					0x00, 0x00, 0x00, 0x00, // Event_id
					0x00, 0x00, 0x00, 0x00, // Event_second
					0x00, 0x00, 0x00, 0x00, // Packet_second
					0x00, 0x00, 0x00, 0x00, // Packet_microsecond
					0x00, 0x00, 0x00, 0x00, // Linktype
					0x00, 0x00, 0x00, 0x04, // Packet_length
					0x00, 0x01, 0x02, 0x03, // Packet_data
				}),
				16,
				func(ctr int) (next int, err error) {
					if ctr == 1 {
						s <- U
					}
					return 100, nil
				},
			)
		},
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if r.Tag != UNIFIED2_PACKET {
				t.Error("Invalid tag received:", r.Tag)
			}
			if _, ok := r.R.(*Unified2Packet); !ok {
				t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
			}
			return true
		},
		"",
	))
	t.Run("read file", testfunc(
		nil,
		nil,
		func(t *testing.T, ctr int, r *Record) bool {
			if testing.Verbose() {
				t.Log("processing record")
			}
			switch {
			case ctr == 2 || ctr == 4:
				if r.Tag != UNIFIED2_PACKET {
					t.Error("Invalid tag received:", r.Tag)
				}
				if _, ok := r.R.(*Unified2Packet); !ok {
					t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
				}
			case ctr == 1 || ctr == 3:
				if r.Tag != UNIFIED2_IDS_EVENT {
					t.Error("Invalid tag received:", r.Tag)
				}
				if _, ok := r.R.(*Unified2IDSEvent_legacy); !ok {
					t.Error("R is wrong type, got:", reflect.TypeOf(r.R))
				}
			}
			return ctr > 3
		},
		"testdata/snort.unified2.1559903814",
	))
}

func TestParseError_Error(t *testing.T) {
	pe := &parseError{
		message: "Test",
		file:    "file.ext",
		error:   anError,
	}

	if err := pe.Error(); err != "file.ext: Test: An Error" {
		t.Error(err, "!=", "file.ext: Test: An Error")
	}
}
