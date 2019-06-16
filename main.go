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

// Main package for u2text program. See
// http://github.com/kazkansouh/u2text for more information.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gopkg.in/Graylog2/go-gelf.v2/gelf"

	"github.com/kazkansouh/u2text/parser"
	"github.com/kazkansouh/u2text/parser/u2"
	"github.com/kazkansouh/u2text/spooler"
)

type stringOps struct {
	// value of option
	value string
	// possible values string can take
	domain []string
}

func (str stringOps) String() string {
	return str.value
}

func (str *stringOps) Set(val string) error {
	for _, opt := range str.domain {
		if opt == val {
			str.value = opt
			return nil
		}
	}
	return fmt.Errorf("Value should be in %q", str.domain)
}

func (s stringOps) usage() string {
	str := "(values "
	for i, opt := range s.domain {
		if i > 0 {
			str = str + ", " + opt
		} else {
			str = str + opt
		}
	}
	str = str + ")"
	return str
}

type stringList struct {
	value []string
	set   bool
}

func (s stringList) String() string {
	str := ""
	for i, opt := range s.value {
		if i > 0 {
			str = str + "," + opt
		} else {
			str = str + opt
		}
	}
	return str
}

func (str *stringList) Set(val string) error {
	val = strings.TrimSpace(val)
	if val == "" {
		return errors.New("Empty argument not allowed")
	}
	if !str.set {
		str.value = strings.Split(val, ",")
	} else {
		str.value = append(str.value, strings.Split(val, ",")...)
		str.set = true
	}
	return nil
}

type markerFile struct {
	marker   *spooler.Marker
	filename string
}

func (m markerFile) String() string {
	if m.marker != nil {
		b, err := json.Marshal(m.marker)
		if err != nil {
			log.Fatal("ERROR: Unable to prepare marker")
		}
		return base64.StdEncoding.EncodeToString(b)
	}
	return ""
}

func (m *markerFile) Set(val string) error {
	var r io.Reader
	if strings.HasPrefix(val, "marker:") {
		r = strings.NewReader(val[7:])
	} else {
		m.filename = val
		file, err := os.Open(val)
		if os.IsNotExist(err) {
			log.Printf("WARNING: Marker file '%s' will be created.\n", m.filename)
			// create file now to ensure permissions are ok
			file, err := os.OpenFile(m.filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
			if err == nil {
				file.Close()
			}
			return err
		}
		if err != nil {
			return err
		}
		defer file.Close()
		r = file
	}

	m.marker = &spooler.Marker{}
	decoder := json.NewDecoder(base64.NewDecoder(base64.StdEncoding, r))
	if err := decoder.Decode(m.marker); err != nil {
		return err
	}
	return nil
}

func (m markerFile) save() error {
	if m.filename == "" || m.marker == nil {
		return nil
	}
	file, err := os.OpenFile(m.filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil
	}
	defer file.Close()
	w := base64.NewEncoder(base64.StdEncoding, file)
	defer w.Close()
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(m.marker); err != nil {
		return err
	}
	return nil
}

type reportEventTemplate struct{}

func (m reportEventTemplate) String() string {
	return ""
}

func (m *reportEventTemplate) Set(val string) error {
	return u2.LoadEventTemplate(val)
}

type reportPacketTemplate struct{}

func (m reportPacketTemplate) String() string {
	return ""
}

func (m *reportPacketTemplate) Set(val string) error {
	return u2.LoadPacketTemplate(val)
}

var (
	// logging destinations
	logGelfServer   string
	logSyslogServer string
	logFile         string

	// log options, setting to hash will include the sha hash in the report too
	logDisplayPacket = stringOps{"hash", []string{"full", "hash"}}

	// report destinations
	reportFile               string
	reportHexDump            bool
	reportShowEventTemplate  bool
	reportShowPacketTemplate bool

	// packet parsing
	parsePackets    = stringOps{"full", []string{"full", "summary", "none"}}
	fullParseFilter = stringList{value: []string{"ip", "data"}} // minimum is "ip data" to support sfPortscan

	// spooler options
	spoolerDir   string
	baseFileName string
	marker       markerFile
	batch        bool

	// meta data files
	sidmsg         string
	genmsg         string
	classification string

	// operating parameters
	workers int
)

func init() {
	flag.StringVar(
		&logGelfServer,
		"log-gelf",
		"",
		"To enable gelf logging, set to server address in "+
			"the format 'address:port'. Only supports UDP.")

	flag.StringVar(
		&logSyslogServer,
		"log-syslog",
		"",
		"To enable syslog logging, set to server address in "+
			"the format 'protocol://address:port'. Where "+
			"protocol is 'tcp' or 'udp'. To log to local "+
			"syslogd, set to 'localhost'.")

	flag.StringVar(
		&logFile,
		"log-file",
		"",
		"To enable logging locally to a file, set to file "+
			"name. Supports setting to '-' to log to stdout.")

	flag.Var(&logDisplayPacket,
		"log-displaypacket",
		"Select whether to include full packet capture in the "+
			"log or only a sha256 hash. Option can be used "+
			"to reduce the size of logs sent to server. "+
			"Note, when set to hash, will also include hash "+
			"in report. "+logDisplayPacket.usage())

	flag.StringVar(
		&reportFile,
		"report-file",
		"",
		"To enable reporting (i.e. text instead of json) to a file, "+
			"set to file name. Supports setting to '-' to report "+
			"to stdout.")

	flag.BoolVar(
		&reportHexDump,
		"report-hex-dump",
		false,
		"When set, includes a hex dump of the packet in report.")

	flag.BoolVar(
		&reportShowEventTemplate,
		"report-show-event-template",
		false,
		"When set, prints default event template and quits.")

	flag.BoolVar(
		&reportShowPacketTemplate,
		"report-show-packet-template",
		false,
		"When set, prints default packet template and quits.")

	flag.Var(&reportEventTemplate{},
		"report-event-template",
		"A go template file to used for printing the events in a "+
			"report. See '-report-show-event-template' for an "+
			"example.")

	flag.Var(&reportPacketTemplate{},
		"report-packet-template",
		"A go template file to used for printing the packets in a "+
			"report. See '-report-show-packet-template' for an "+
			"example.")

	flag.Var(&parsePackets,
		"tshark-level",
		"Set level of parsing performed by TShark for captured "+
			"packets. Full will pass the -P and -V option, summary "+
			"will pass the -P option and none will disable using "+
			"tshark. Caution, to correctly process portscan "+
			"packets, it is required to set this to full. Using "+
			"full results in a detailed output in the log, "+
			"whereas the report typically only uses the result "+
			"of one line summary (if available). "+parsePackets.usage())

	flag.Var(&fullParseFilter,
		"tshark-filter",
		"When performing a full parse with TShark filter the included"+
			"layers in the json to reduce the total size of the "+
			"log message. The value is passed to TShark by the -J "+
			"option. Option can be given multiple times, or given "+
			"a comma separated list. Caution, when processing "+
			"portscan events it is required to set this to include "+
			"both 'ip' and 'data' layers.")

	flag.StringVar(
		&spoolerDir,
		"spooler-directory",
		"/var/log/snort/",
		"Specify location where the unified2 log files are written "+
			"to by snort.")

	flag.StringVar(
		&baseFileName,
		"spooler-base-filename",
		"snort.u2",
		"The name of the unified2 files generated by snort "+
			"(excluding the timestamp).")

	flag.Var(&marker,
		"spooler-marker",
		"File that bookmarks the position of a previous operation "+
			"(similar to waldo in barnyard). If file does not "+
			"exist, then program will start from the first file "+
			"and it will be created on program exit. If value is "+
			"prefixed with 'marker:' then it will be directly "+
			"interpreted as the base64 value of the marker, "+
			"however, it will not be updated on program exit.")

	flag.BoolVar(
		&batch,
		"spooler-batch",
		false,
		"Run in batch mode. Read all available records then quit.")

	flag.StringVar(
		&sidmsg,
		"meta-sidmsg",
		"/etc/snort/sid-msg.map",
		"Location of 'sid-msg.map' file, if not available use empty file.")

	flag.StringVar(
		&genmsg,
		"meta-genmsg",
		"/etc/snort/gen-msg.map",
		"Location of 'gen-msg.map' file, if not available use empty file.")

	flag.StringVar(
		&classification,
		"meta-classification",
		"/etc/snort/classification.config",
		"Location of 'classification.config' file, if not available use empty file.")

	flag.IntVar(
		&workers,
		"operation-workers",
		1,
		"Number of workers used for post-processing of events. Must be >=1. "+
			"Useful when using TShark to parse packets, as each packet is "+
			"individually piped to a TShark process, thus increasing value "+
			"will result in an increased throughput. However, if value is "+
			">1, events will be logged/reported out of order.")
}

// type with one value, i.e. unit type
type unit struct{}

// channel of units, used for routine synchronisation
type tracker chan unit

// convenience definition of unit value
var U unit = unit{}

func printConfig() {
	log.Println("u2text: Copyright 2019, Karim Kanso")
	log.Println("")
	log.Println("Configuration:")

	vars := map[string]map[string]interface{}{
		"Logging": map[string]interface{}{
			"Enable gelf":        logGelfServer != "",
			"Gelf server":        logGelfServer,
			"Enable syslog":      logSyslogServer != "",
			"Syslog server":      logSyslogServer,
			"Log to file":        logFile != "",
			"Logging file":       logFile,
			"Log display packet": logDisplayPacket.String(),
		},
		"Reporting": map[string]interface{}{
			"Enable reporting":               reportFile != "",
			"Report file":                    reportFile,
			"Show packet hash in report":     logDisplayPacket.String() == "hash",
			"Show packet hex dump in report": reportHexDump,
		},
		"TShark": map[string]interface{}{
			"Parse level":     parsePackets.String(),
			"Filter layers":   len(fullParseFilter.value) > 0,
			"Included layers": fullParseFilter.value,
		},
		"Spooler": map[string]interface{}{
			"Snort logging directory": spoolerDir,
			"Unified2 base file name": baseFileName,
			"Marker file":             marker.filename,
			"Marker":                  marker.marker,
			"Batch mode":              batch,
		},
		"Meta data": map[string]interface{}{
			"sid-msg.map location":           sidmsg,
			"gen-msg.map location":           genmsg,
			"classification.config location": classification,
		},
		"General options": map[string]interface{}{
			"Packet processing workers": workers,
		},
	}

	for name, block := range vars {
		log.Println("  ", name)
		for k, v := range block {
			switch v.(type) {
			case []string:
				log.Printf("    %s: %T:%q\n", k, v, v)
			default:
				log.Printf("    %s: %T:%#v\n", k, v, v)
			}
		}
	}

	log.Println("")
}

func main() {
	flag.Parse()

	// Process special commands first
	if reportShowEventTemplate {
		fmt.Println(u2.EventTemplate)
		return
	}
	if reportShowPacketTemplate {
		fmt.Println(u2.PacketTemplate)
		return
	}

	printConfig()

	if workers < 1 {
		log.Fatal("ERROR: the number of workers must be at least 1")
	}

	// Read meta data from config files
	mmap, err := parser.ParseMaps(
		sidmsg,
		genmsg,
		classification)
	if err != nil {
		log.Fatal(err)
	}

	// Setup outputs by adding writers to this slice that can receive json objects
	logWriters := []io.Writer{}
	switch logFile {
	case "":
	case "-":
		logWriters = append(logWriters, os.Stdout)
	default:
		if file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640); err != nil {
			log.Fatal(err)
		} else {
			defer file.Close()
			logWriters = append(logWriters, file)
		}
	}
	if logGelfServer != "" {
		gelfWriter, err := gelf.NewUDPWriter(logGelfServer)
		if err != nil {
			log.Fatal(err)
		}
		defer gelfWriter.Close()
		logWriters = append(logWriters, gelfWriter)
	}
	if logSyslogServer != "" {
		network := ""
		switch {
		case strings.HasPrefix(logSyslogServer, "tcp://"):
			network = "tcp"
			logSyslogServer = logSyslogServer[6:]
		case strings.HasPrefix(logSyslogServer, "udp://"):
			network = "udp"
			logSyslogServer = logSyslogServer[6:]
		case logSyslogServer == "localhost":
			logSyslogServer = ""
		default:
			log.Fatalf("ERROR: specified syslog server (%s) should begin with udp:// or tcp:// or be set to localhost.", logSyslogServer)
		}
		syslogWriter, err := syslog.Dial(network, logSyslogServer, syslog.LOG_ALERT|syslog.LOG_LOCAL4, "")
		if err != nil {
			log.Fatal(err)
		}
		defer syslogWriter.Close()
		logWriters = append(logWriters, syslogWriter)
	}
	jsonEncoder := json.NewEncoder(io.MultiWriter(logWriters...))

	// Setup outputs by adding writers to this slice that can receive text report
	reportWriters := []io.Writer{}
	switch reportFile {
	case "":
	case "-":
		reportWriters = append(reportWriters, os.Stdout)
	default:
		if file, err := os.OpenFile(logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640); err != nil {
			log.Fatal(err)
		} else {
			defer file.Close()
			reportWriters = append(reportWriters, file)
		}
	}
	reportWriter := io.MultiWriter(reportWriters...)

	// Start the spooler
	spool := spooler.NewSpooler(spoolerDir, baseFileName)
	result := spool.Start(marker.marker)

	// To reduce the processing time each record when using TShark
	// to parse packets, each record is processed in its own go
	// routine. The below channel is used to track when these
	// routines are complete
	track_start := make(tracker, 0)
	track_end := make(tracker, workers)

	// Enter main loop, processing records as they are received
	go func() {
		defer func() {
			track_end <- U
		}()

		for {
			if r, ok := <-result; !ok {
				break
			} else {
				r.BondMessageMap(mmap)
				track_start <- U

				// asynchronously process event log
				go func() {
					defer func() {
						track_end <- U
					}()

					// prepare packet for logging
					switch r.R.(type) {
					case *u2.Unified2Packet:
						pkt := r.R.(*u2.Unified2Packet)
						switch parsePackets.value {
						case "full":
							pkt.DecodePacket(false, fullParseFilter.value)
						case "summary":
							pkt.DecodePacket(true, fullParseFilter.value)
						case "none":
							pkt.Packet = nil
						default:
							log.Fatalf("ERROR: invalid value for parse packets: %s\n", parsePackets.value)
						}
						switch logDisplayPacket.value {
						case "full":
						case "hash":
							pkt.CalculateHash()
							pkt.Packet_data = nil
						default:
							log.Fatalf("ERROR: invalid value for display packet: %s\n", logDisplayPacket.value)
						}
					default:
					}
					if len(logWriters) > 0 {
						if err := jsonEncoder.Encode(r.R); err != nil {
							log.Println(err.Error())
						}
					}

					// prepare packet for reporting
					if pkt, ok := r.R.(*u2.Unified2Packet); ok {
						if reportHexDump {
							pkt.RestorePacketData()
						} else {
							pkt.Packet_data = nil
						}
					}
					if wrtr, ok := r.R.(io.WriterTo); ok && len(reportWriters) > 0 {
						if _, err := wrtr.WriteTo(reportWriter); err != nil {
							log.Fatal("ERROR: unable to pretty print record: ", err.Error())
						}
					}
				}()
			}
		}
	}()

	// placeholder channel to receive record location of final
	// record that was parsed
	var lastmarker <-chan spooler.Marker

	// shutdown spooler when it reads last available record if
	// running in batch mode
	if batch {
		lastmarker = spool.Stop(true)
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	// wait for all routines to complete
	i := 0
	for {
		if i < workers {

			select {
			case <-track_start:
				i++
			case <-track_end:
				i--
			case sig := <-signals:
				log.Println("Shutdown requested (", sig, ")")
				lastmarker = spool.Stop(false)
			}

		} else {
			<-track_end
			i--
		}
		if i < 0 {
			break
		}

	}

	log.Println("Parsing finished")

	if lastmarker != nil {
		m := <-lastmarker
		marker.marker = &m
		log.Println("Marker:", marker.String())
		if err := marker.save(); err != nil {
			log.Println("WARNING: Unable to save marker: ", err.Error())
		}
	} else {
		log.Println("WARNING: Last marker not available")
	}
}
