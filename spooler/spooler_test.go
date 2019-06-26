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

package spooler

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"runtime/pprof"
	"testing"
	"time"

	"gotest.tools/assert"

	"github.com/fsnotify/fsnotify"

	"github.com/kazkansouh/u2text/parser/u2"
)

// utility function to copy a file
func copyfile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return err
}

var anError = errors.New("An Error")

func TestSpoolError(t *testing.T) {
	t.Run("nominal", func(t *testing.T) {
		e := spoolError{
			message:   "msg",
			ErrorCode: E_WatcherSpoolerDirectoryList,
			error:     anError,
		}

		assert.Equal(t, e.Error(), "msg: "+anError.Error())
		assert.Equal(t, e.NextError(), anError)
		assert.Equal(t, e.Code(), E_WatcherSpoolerDirectoryList)
	})

	t.Run("no-error", func(t *testing.T) {
		e := spoolError{
			message:   "msg",
			ErrorCode: E_WatcherSpoolerDirectoryList,
		}

		assert.Equal(t, e.Error(), "msg")
		assert.Equal(t, e.NextError(), nil)
		assert.Equal(t, e.Code(), E_WatcherSpoolerDirectoryList)
	})
}

type mockWatcher struct {
	ctx  interface{}
	AF   func(ctx interface{}, name string) error
	CF   func(ctx interface{}) error
	EVTF func(ctx interface{}) <-chan fsnotify.Event
	ERRF func(ctx interface{}) <-chan error
}

func (w *mockWatcher) EventC() <-chan fsnotify.Event {
	if w.EVTF == nil {
		return nil
	}
	return w.EVTF(w.ctx)
}

func (w *mockWatcher) ErrorC() <-chan error {
	if w.ERRF == nil {
		return nil
	}
	return w.ERRF(w.ctx)
}

func (w *mockWatcher) Add(name string) error {
	if w.AF == nil {
		return nil
	}
	return w.AF(w.ctx, name)
}

func (w *mockWatcher) Close() error {
	if w.CF == nil {
		return nil
	}
	return w.CF(w.ctx)
}

func TestSpoolerSync(t *testing.T) {
	newWatcherOriginal := newWatcher
	readDirOriginal := readDir
	statOriginal := stat

	type test struct {
		name      string
		marker    *Marker
		expected  []*u2.Record
		newmarker *Marker
		// only check expected and offset in marker in actual
		// are >= expected data
		upto    bool
		err     string
		errcode ErrorCode
		setup   func(t *testing.T, name string, spooler *spooler, step int)
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			dir, err := ioutil.TempDir("", test.name)
			assert.NilError(t, err)
			defer os.RemoveAll(dir)

			spooler, spoolertypeok := NewSpooler(dir, "snort.unified2").(*spooler)
			assert.Assert(t, spoolertypeok)

			results := make(chan *u2.Record, 0)

			test.setup(t, test.name, spooler, 0)
			defer test.setup(t, test.name, spooler, -1)

			done := make(chan struct{}, 0)
			go func() {
				defer close(done)
				newmarker, err := spooler.SyncStart(test.marker, results)
				if test.err != "" {
					assert.ErrorContains(t, err, test.err)
					if sperr, ok := err.(SpoolError); ok {
						assert.Equal(t, sperr.Code(), test.errcode)
					} else {
						t.Fatal("Unexpected type of error received:", reflect.TypeOf(err))
					}
				} else {
					assert.NilError(t, err)
				}
				if test.upto {
					assert.Assert(t, newmarker != nil)
					assert.Assert(t, newmarker.File >= test.newmarker.File)
					if newmarker.File == test.newmarker.File {
						assert.Assert(t, newmarker.Offset >= test.newmarker.Offset)
					}
				} else {
					assert.DeepEqual(t, newmarker, test.newmarker)
				}
			}()
			defer func() {
			loop:
				for {
					select {
					case _, ok := <-results:
						if !ok {
							break loop
						}
					case <-time.NewTimer(time.Second * 5).C:
						pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
						t.Fatal("Timeout in cleanup1")
					}

				}

				select {
				case <-done:
				case <-time.NewTimer(time.Second * 10).C:
					t.Fatal("Timeout in cleanup2")
				}
			}()

			test.setup(t, test.name, spooler, 1)

		loop:
			for i := 0; true; i++ {
				select {
				case record, ok := <-results:
					if !ok {
						if test.upto {
							assert.Assert(t, i >= len(test.expected))
						} else {
							assert.Equal(t, i, len(test.expected))
						}
						break loop
					}
					if !test.upto || i < len(test.expected) {
						assert.Assert(t, i < len(test.expected))
						assert.Equal(t, record.Tag, test.expected[i].Tag)
						assert.Equal(t, filepath.Base(record.FileName), test.expected[i].FileName)

						t.Log("Record:", i, "ok at offset", record.Offset)
					} else {
						t.Log("Record:", i, "skipped at offset", record.Offset)
					}
				case <-time.NewTimer(time.Second * 10).C:
					t.Fatal("Timeout waiting for next record")
				}

				test.setup(t, test.name, spooler, i+2)
			}
		}
	}

	R := func(tag uint32, fname string) *u2.Record {
		return &u2.Record{
			Tag:      tag,
			FileName: fname,
		}
	}

	LoadFile := func(t *testing.T, name, logdir string) {
		dest := filepath.Join(logdir, name)
		t.Log("loading: ", dest)
		assert.NilError(t, copyfile(filepath.Join("testdata", name), dest))
	}

	for _, test := range []*test{
		&test{
			name:      "no-file-graceful",
			expected:  []*u2.Record{},
			newmarker: nil,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					if testing.Short() {
						t.Skip("skipping test has a delay")
					}
				case 1:
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name:      "no-file-brutal",
			expected:  []*u2.Record{},
			newmarker: nil,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					if testing.Short() {
						t.Skip("skipping test has a delay")
					}
				case 1:
					assert.Assert(t, s.Stop(false))
				}
			},
		},
		&test{
			name: "single-file-start-graceful",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
				R(2, "snort.unified2.1560420495"),
			},
			newmarker: &Marker{"snort.unified2.1560420495", 279},
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				case 1:
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name:      "single-file-start-brutal",
			expected:  []*u2.Record{},
			newmarker: &Marker{"snort.unified2.1560420495", 0},
			upto:      true,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				case 1:
					assert.Assert(t, s.Stop(false))
				}
			},
		},
		&test{
			name: "single-file-start-brutal-midway",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560419045"),
			},
			newmarker: &Marker{"snort.unified2.1560419045", 60},
			upto:      true,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560419045", s.logdir)
				case 2:
					assert.Assert(t, s.Stop(false))
					t.Log("brutal request")
				}
			},
		},
		&test{
			name: "multi-file-start-graceful",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
				R(2, "snort.unified2.1560420495"),
				R(7, "snort.unified2.1560546773"),
				R(2, "snort.unified2.1560546773"),
			},
			newmarker: &Marker{"snort.unified2.1560546773", 279},
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
					LoadFile(t, "snort.unified2.1560546773", s.logdir)
				case 1:
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name: "multi-file-start-brutal-midway-1",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
			},
			newmarker: &Marker{"snort.unified2.1560420495", 60},
			upto:      true,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
					LoadFile(t, "snort.unified2.1560546773", s.logdir)
				case 2:
					assert.Assert(t, s.Stop(false))
				}
			},
		},
		&test{
			name: "multi-file-start-brutal-midway-2",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
				R(2, "snort.unified2.1560420495"),
			},
			newmarker: &Marker{"snort.unified2.1560420495", 279},
			upto:      true,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
					LoadFile(t, "snort.unified2.1560546773", s.logdir)
				case 3:
					assert.Assert(t, s.Stop(false))
				}
			},
		},
		&test{
			name: "multi-file-start-brutal-midway-3",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
				R(2, "snort.unified2.1560420495"),
				R(7, "snort.unified2.1560546773"),
			},
			newmarker: &Marker{"snort.unified2.1560546773", 60},
			upto:      true,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
					LoadFile(t, "snort.unified2.1560546773", s.logdir)
				case 4:
					assert.Assert(t, s.Stop(false))
				}
			},
		},
		&test{
			name: "single-file-midway-graceful",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
				R(2, "snort.unified2.1560420495"),
			},
			newmarker: &Marker{"snort.unified2.1560420495", 279},
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
				case 1:
					<-s.watcherReady
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				case 2:
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name: "single-file-start-graceful-marker",
			expected: []*u2.Record{
				R(2, "snort.unified2.1560420495"),
			},
			marker:    &Marker{"snort.unified2.1560420495", 60},
			newmarker: &Marker{"snort.unified2.1560420495", 279},
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				case 1:
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name:      "single-file-start-bad-marker",
			expected:  []*u2.Record{},
			marker:    &Marker{"snort.unified2.1560420495", 5000},
			newmarker: &Marker{"snort.unified2.1560420495", 5000},
			err:       "Unable to seek",
			errcode:   E_Parse,
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				}
			},
		},
		&test{
			name: "single-file-midway-graceful-marker-nonfile",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560546773"),
				R(2, "snort.unified2.1560546773"),
			},
			marker:    &Marker{"snort.unified2.1560420496", 0},
			newmarker: &Marker{"snort.unified2.1560546773", 279},
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 1:
					<-s.watcherReady
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
					LoadFile(t, "snort.unified2.1560546773", s.logdir)
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name:    "new-watcher-fail",
			err:     "An Error",
			errcode: E_Watcher,
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case -1:
					newWatcher = newWatcherOriginal
				case 0:
					newWatcher = func() (Watcher, error) {
						return nil, anError
					}
				}
			},
		},
		&test{
			name:    "watcher-add-fail",
			err:     "An Error",
			errcode: E_Watcher,
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case -1:
					newWatcher = newWatcherOriginal
				case 0:
					newWatcher = func() (Watcher, error) {
						return &mockWatcher{
							AF: func(ctx interface{}, name string) error {
								return anError
							},
						}, nil
					}
				}
			},
		},
		&test{
			name:    "watcher-error-on-channel",
			err:     "An Error",
			errcode: E_Watcher,
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case -1:
					newWatcher = newWatcherOriginal
				case 0:
					newWatcher = func() (Watcher, error) {
						type X struct {
							W  *fsnotify.Watcher
							EC chan error
						}
						w, err := fsnotify.NewWatcher()
						ec := make(chan error, 1)
						ec <- anError
						return &mockWatcher{
							ctx: X{w, ec},
							AF: func(ctx interface{}, name string) error {
								return ctx.(X).W.Add(name)
							},
							CF: func(ctx interface{}) error {
								close(ctx.(X).EC)
								return ctx.(X).W.Close()
							},
							EVTF: func(ctx interface{}) <-chan fsnotify.Event {
								return ctx.(X).W.Events
							},
							ERRF: func(ctx interface{}) <-chan error {
								return ctx.(X).EC
							},
						}, err
					}
				}
			},
		},
		&test{
			name:    "read-spooldir-fail",
			err:     "An Error",
			errcode: E_WatcherSpoolerDirectoryList,
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case -1:
					readDir = readDirOriginal
				case 0:
					if testing.Short() {
						t.Skip("skipping test has a delay")
					}
					readDir = func(name string) ([]os.FileInfo, error) {
						return nil, anError
					}
				}
			},
		},
		&test{
			name:    "watcher-stat-fail",
			err:     "An Error",
			errcode: E_WatcherStat,
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case -1:
					stat = statOriginal
				case 0:
					if testing.Short() {
						t.Skip("skipping test has a delay")
					}
					stat = func(name string) (os.FileInfo, error) {
						return nil, anError
					}
				case 1:
					<-s.watcherReady
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				}
			},
		},
		&test{
			name:      "no-file-postgraceful",
			expected:  []*u2.Record{},
			newmarker: nil,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					if testing.Short() {
						t.Skip("skipping test has a delay")
					}
				case 1:
					assert.Assert(t, s.Stop(true))
				case -1:
					assert.Assert(t, !s.Stop(true))
				}
			},
		},
		&test{
			name: "single-file-start-graceful-double",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
				R(2, "snort.unified2.1560420495"),
			},
			newmarker: &Marker{"snort.unified2.1560420495", 279},
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				case 3:
					assert.Assert(t, s.Stop(true))
					assert.Assert(t, s.Stop(true))
				}
			},
		},
	} {
		t.Run(test.name, testfunc(test))
	}
}

func TestSpoolerStart(t *testing.T) {
	type test struct {
		name      string
		marker    *Marker
		expected  []*u2.Record
		newmarker *Marker
		// only check expected and offset in marker in actual
		// are >= expected data
		upto    bool
		err     string
		errcode ErrorCode
		setup   func(t *testing.T, name string, spooler *spooler, step int)
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			dir, err := ioutil.TempDir("", test.name)
			assert.NilError(t, err)
			defer os.RemoveAll(dir)

			spooler, spoolertypeok := NewSpooler(dir, "snort.unified2").(*spooler)
			assert.Assert(t, spoolertypeok)

			test.setup(t, test.name, spooler, 0)
			defer test.setup(t, test.name, spooler, -1)

			results, newmarker := spooler.Start(test.marker)

			defer func() {
			loop:
				for {
					select {
					case _, ok := <-results:
						if !ok {
							break loop
						}
					case <-time.NewTimer(time.Second * 5).C:
						pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
						t.Fatal("Timeout in cleanup1")
					}

				}

				select {
				case err, ok := <-spooler.ErrorC():

					if test.err != "" {
						assert.Assert(t, ok)
						assert.ErrorContains(t, err, test.err)
						if sperr, ok := err.(SpoolError); ok {
							assert.Equal(t, sperr.Code(), test.errcode)
						} else {
							t.Fatal("Unexpected type of error received:", reflect.TypeOf(err))
						}

						select {
						case _, ok := <-spooler.ErrorC():
							assert.Assert(t, !ok)
						case <-time.NewTimer(time.Second * 2).C:
							t.Fatal("Timeout waiting for error channel to close")
						}

					} else {
						assert.Assert(t, !ok)
					}
				case <-time.NewTimer(time.Second * 2).C:
					t.Fatal("Timeout in waiting for errors")
				}

				select {
				case lastmarker, ok := <-newmarker:
					assert.Assert(t, ok)

					if test.upto {
						assert.Assert(t, lastmarker.File >= test.newmarker.File)
						if lastmarker.File == test.newmarker.File {
							assert.Assert(t, lastmarker.Offset >= test.newmarker.Offset)
						}
					} else {
						assert.DeepEqual(t, lastmarker, test.newmarker)
					}
					select {
					case _, ok := <-newmarker:
						assert.Assert(t, !ok)
					case <-time.NewTimer(time.Second * 2).C:
						t.Fatal("Timeout in for newmarker channel to close")
					}
				case <-time.NewTimer(time.Second * 2).C:
					t.Fatal("Timeout in waiting for newmarker")
				}
			}()

			test.setup(t, test.name, spooler, 1)

		loop:
			for i := 0; true; i++ {
				select {
				case record, ok := <-results:
					if !ok {
						if test.upto {
							assert.Assert(t, i >= len(test.expected))
						} else {
							assert.Equal(t, i, len(test.expected))
						}
						break loop
					}
					if !test.upto || i < len(test.expected) {
						assert.Assert(t, i < len(test.expected))
						assert.Equal(t, record.Tag, test.expected[i].Tag)
						assert.Equal(t, filepath.Base(record.FileName), test.expected[i].FileName)

						t.Log("Record:", i, "ok at offset", record.Offset)
					} else {
						t.Log("Record:", i, "skipped at offset", record.Offset)
					}
				case <-time.NewTimer(time.Second * 10).C:
					t.Fatal("Timeout waiting for next record")
				}

				test.setup(t, test.name, spooler, i+2)
			}
		}
	}

	R := func(tag uint32, fname string) *u2.Record {
		return &u2.Record{
			Tag:      tag,
			FileName: fname,
		}
	}

	LoadFile := func(t *testing.T, name, logdir string) {
		dest := filepath.Join(logdir, name)
		t.Log("loading: ", dest)
		assert.NilError(t, copyfile(filepath.Join("testdata", name), dest))
	}

	for _, test := range []*test{
		&test{
			name:      "no-file-graceful",
			expected:  []*u2.Record{},
			newmarker: nil,
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					if testing.Short() {
						t.Skip("skipping test has a delay")
					}
				case 1:
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name: "single-file-start-graceful",
			expected: []*u2.Record{
				R(7, "snort.unified2.1560420495"),
				R(2, "snort.unified2.1560420495"),
			},
			newmarker: &Marker{"snort.unified2.1560420495", 279},
			err:       "",
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				case 1:
					assert.Assert(t, s.Stop(true))
				}
			},
		},
		&test{
			name:      "single-file-start-bad-marker",
			expected:  []*u2.Record{},
			marker:    &Marker{"snort.unified2.1560420495", 5000},
			newmarker: &Marker{"snort.unified2.1560420495", 5000},
			err:       "Unable to seek",
			errcode:   E_Parse,
			setup: func(t *testing.T, name string, s *spooler, step int) {
				switch step {
				case 0:
					LoadFile(t, "snort.unified2.1560420495", s.logdir)
				}
			},
		},
	} {
		t.Run(test.name, testfunc(test))
	}
}
