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

// Extract ids events from a logging directory. Scans directory for
// new files and adds them to the processing list.
package spooler

import (
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/kazkansouh/u2text/parser"
	"github.com/kazkansouh/u2text/parser/u2"
)

// File and offset within the file that has been processed
// already. Assumes events in files which have in lexicographical
// order less than the indicated file have been processed.
type Marker struct {
	File   string
	Offset int64
}

// Stores all state information needed by spooler
type Spooler struct {
	basename    string
	logdir      string
	shutdown    chan bool
	watcher     *fsnotify.Watcher
	watcherdone chan struct{}
	processdone chan Marker
	todo        chan string
	done        Marker
}

// watch directory for new files
func (s *Spooler) watch() {
	defer func() {
		s.watcherdone <- struct{}{}
	}()
	for {
		select {
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Create == fsnotify.Create {
				f, err := os.Open(event.Name)
				if err != nil {
					log.Fatal(err)
				}
				fi, err := f.Stat()
				f.Close()
				if err != nil {
					log.Fatal(err)
				}
				if !fi.IsDir() && strings.HasPrefix(fi.Name(), s.basename) {
					s.todo <- fi.Name()
				}
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			log.Fatal(err)
		}
	}
}

// manages which file to parse
func (s *Spooler) process(result chan<- *u2.Record) {
	defer func() {
		s.processdone <- s.done
	}()
	var clientresult <-chan *u2.Record
	var clientshutdown chan *u2.Unit

	timer := time.NewTimer(0)
	<-timer.C

	// caller has requested shutdown at end of records
	batch := false
	// caller has requested showdown now
	brutal := false
	// a new file is pending to be read
	var newpending string = ""
loop:
	for {
		if newpending == "" && !brutal {
			// continue used in following to quickly
			// populate newpending with next file to
			// process
			select {
			case file := <-s.todo:
				// skip processed files
				if file < s.done.File {
					log.Println("WARNING: Skipping log file: ", file)
					continue
				}
				if file == s.done.File {
					if clientresult == nil {
						// continue processing
						clientshutdown = make(chan *u2.Unit, 1)
						clientresult = parser.ParseU2(filepath.Join(s.logdir, file), s.done.Offset, clientshutdown)
						if batch && clientshutdown != nil {
							clientshutdown <- u2.U
						}
					}
					continue
				} else {
					if clientresult == nil {
						// new file
						s.done.File = file
						s.done.Offset = 0
						clientshutdown = make(chan *u2.Unit, 1)
						clientresult = parser.ParseU2(filepath.Join(s.logdir, file), 0, clientshutdown)
						if batch && clientshutdown != nil {
							clientshutdown <- u2.U
						}
						continue

					} else {
						// already parsing file, request graceful shutdown
						log.Println("Newfile pending: " + file)
						if !batch && clientshutdown != nil {
							// already notified in batch mode
							clientshutdown <- u2.U
						}
						newpending = file
					}
				}
			default:
			}
		}

		select {
		case graceful := <-s.shutdown:
			if graceful {
				batch = true
				log.Println("Shutdown requested (graceful)")
				if clientshutdown != nil {
					clientshutdown <- u2.U
				}
			} else {
				brutal = true
				log.Println("Shutdown requested (brutal)")
				newpending = ""
				if clientshutdown != nil {
					close(clientshutdown)
					clientshutdown = nil
				}
			}

		default:
		}

		timer.Reset(time.Millisecond * 100)

	clientresult:
		select {
		case record, ok := <-clientresult:
			// clean up timer state
			if !timer.Stop() {
				<-timer.C
			}
			if !ok {
				if newpending != "" {
					// client ended, start on next file
					s.done.File = newpending
					s.done.Offset = 0
					clientshutdown = make(chan *u2.Unit, 1)
					clientresult = parser.ParseU2(filepath.Join(s.logdir, newpending), 0, clientshutdown)
					if batch {
						clientshutdown <- u2.U
					}
					newpending = ""
				} else {
					close(result)
					break loop
				}
				break clientresult
			}
			s.done.Offset = record.Offset
			result <- record
		case <-timer.C:
		}

	}
}

// Stops processing events and release resources.
//
// When graceful is true, stops watching for new files and then
// processes all events available (i.e. it runs in batch mode). When
// false, it will sharply end the processing mid-file.
//
// The returned channel will contain the position that was reached.
func (s *Spooler) Stop(graceful bool) <-chan Marker {
	s.shutdown <- graceful
	if s.watcher != nil {
		s.watcher.Close()
		<-s.watcherdone
		s.watcher = nil
	}
	return s.processdone
}

// Create a new instance of a spooler for a given logdir. Searches for
// files which start with basename in logidr.
func NewSpooler(logdir, basename string) *Spooler {
	return &Spooler{
		basename:    basename,
		logdir:      logdir,
		shutdown:    make(chan bool, 1),
		watcherdone: make(chan struct{}, 0),
		processdone: make(chan Marker, 0),
		todo:        make(chan string, 100),
	}
}

// Run the spooler, read records are returned in the channel
func (s *Spooler) Start(marker *Marker) <-chan *u2.Record {
	var err error
	if s.watcher, err = fsnotify.NewWatcher(); err != nil {
		log.Fatal(err)
	}

	// start watching log directory before scanning to ensure
	// there is no gap in detecting added files
	if err = s.watcher.Add(s.logdir); err != nil {
		log.Fatal(err)
	}

	// save start point
	if marker != nil {
		s.done = *marker
	}

	// start the main processing loop
	result := make(chan *u2.Record, 50)
	go s.process(result)

	files, err := ioutil.ReadDir(s.logdir)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		if !file.IsDir() && strings.HasPrefix(file.Name(), s.basename) {
			s.todo <- file.Name()
		}
	}

	// add any new files that arrive to queue
	go s.watch()

	// scan directory for files and add them to s.todo
	return result
}
