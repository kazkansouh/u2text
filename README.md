# Unified2 log parser for Go - u2text

[![Build Status](https://travis-ci.org/kazkansouh/u2text.svg?branch=master)](https://travis-ci.org/kazkansouh/u2text)

This code (`u2text`) was written primarily as a tool with a functional
and clean interface that has a small number of runtime dependencies to
post-process the [Snort][snort] unified2 log files in a lab
environment. While setting up a lab I became frustrated with other
tools that are available as many are becoming dated/un-maintained
(i.e. implies compatibility issues) and none of the ones I tried
satisfactorily provided both a clean text output (as I typically run
`snort` within Docker its something that is useful for quick tests) as
well as logging to a remote server in a meaningful way (e.g. ability
to control full packet captures).

There are other tools such as [*Sguil*][sguil] which are much holistic
in scope. However, `u2text` should be seen as something analogous to
[*barnyard2*][barnyard2] tuned to my requirements (and modernised for
JSON).

The following features are present:

* Support for using [TShark][tshark] (command line version of
  *WireShark*) to parse packet captures before sending to logging
  server.
    * Multiple levels:
        1. `none`: do not use *TShark*
        2. `summary`: generate a one line summary of the packet
           (similar to what *WireShark* will show).
        3. `full`: Apply the standard dissectors to the packet to
           obtain a JSON object. See `-T ek -P -V` options for
           *TShark*.

            To reduce the size of information sent to the logging
            server, it possible to filter the layers included in
            the output. See the `-J` option for TShark.
* Support for interpreting `sfPortscan` payloads (see the *Snort*
  manual). Requires that `u2text` is run with *TShark* at the `full`
  level and at minimum the `ip` and `data` layers are not
  filtered. This is because packet parsing is provided by *TShark*.
* To save sending full packet captures to log server, a mini http
  server is included that serves `PCAP` files and tags the log entry
  with a url to download the packet. This combined with the full
  packet parsing offers a powerful interface to both provide indexable
  packet fields (e.g. http headers) in the log server without the need
  to store large (potentially 65KB) binary data.
* Support for parsing the `sid-msg.map`, `gen-msg.map` and
  `classification.config` files to translate numeric values into
  textual values.
* Log entries are produced in JSON and the supported destinations
  include: [*Graylog*][graylog] (via [GELF][gelf] (UDP)), Syslog or to
  a local file. It is recommended to use GELF as it supports larger
  messages than Syslog.
    * Adding additional outputs is simple, it requires adding a
      `io.Writer` that can receive JSON objects.
* Text based report that can be output to either the terminal or a
  local file.
    * It is possible to provide [custom templates](#custom-templates)
      to change the report format.
* Continuous or Batch operation (similar to [*barnyard2*][barnyard2]).
* Support for resuming processing from the location previous execution
  was stopped. Similar to a *waldo* file in [*barnyard2*][barnyard2].

Both *u2spewfoo* (part of *Snort*) and [*barnyard2*][barnyard2] were
used as inspiration for the program. The main functional difference
with *barnyard2* is that *u2text* does not cache events to correlate
events with packets. The design choice of *u2text* is to rely on a
SIEM (Security Information and Event Management) system to provide
correlation. While developing [Graylog][garylog] was used for this
feature (via GELF interface) where its trivial to search for related
events/packets.

Currently the extra data records in the unified2 logs are not
processed, and a warning is printed to the terminal.

## Baseline

The program was developed against the following:

* Snort 2.9.13.0
* TShark (Wireshark) 2.6.8
* Graylog 3.0.1

## Usage

The program is available in the standard `go` way:

```
go get github.com/kazkansouh/u2text
```

The sub-packages of the program can be taken to parse the unified2
files independently. That is, the [`parser`][parser]`/`[`u2`][u2]
package has all the code needed to parse a single unified2 file and
the [`spooler`][spooler] package has all the code to track multiple
unified2 files.

To run `u2text` to report to stdout with hex dumps run the following
command:

```
$ u2text \
    -spooler-directory=/var/log/snort \
    -meta-sidmsg /etc/snort/sid-msg.map \
    -meta-genmsg /etc/snort/gen-msg.map \
    -meta-classification /etc/snort/classification.config \
    -spooler-marker=/var/log/snort/marker \
    -tshark-level=full \
    -report-hex-dump \
    -report-file -
```

The following options are available:

```
$ u2text -help
Usage of u2text:
  -log-displaypacket value
        Select whether to include full packet capture in the log or only a sha256 hash. Option can be used to reduce the size of logs sent to server. Note, when set to hash, will also include hash in report. (values full, hash) (default hash)
  -log-file string
        To enable logging locally to a file, set to file name. Supports setting to '-' to log to stdout.
  -log-gelf string
        To enable gelf logging, set to server address in the format 'address:port'. Only supports UDP.
  -log-packet-server-bind-address string
        Location to bind the server to. (default "0.0.0.0:8865")
  -log-packet-server-directory string
        Directory that the packet server uses to save packets to. Files will be pcaps that have the hash of the underlying packet as the filename. (default "packetcache")
  -log-packet-server-presentation string
        Requires '-log-display-packet=hash'. When set, enables a http server that makes pcap files available (where the name of the file is the hash). The value of this should be the base external url of this host, e.g. 'http://1.2.3.4:8865' that will be entered into log entries to link to the pcap file.
  -log-syslog string
        To enable syslog logging, set to server address in the format 'protocol://address:port'. Where protocol is 'tcp' or 'udp'. To log to local syslogd, set to 'localhost'.
  -meta-classification string
        Location of 'classification.config' file, if not available use empty file. (default "/etc/snort/classification.config")
  -meta-genmsg string
        Location of 'gen-msg.map' file, if not available use empty file. (default "/etc/snort/gen-msg.map")
  -meta-sidmsg string
        Location of 'sid-msg.map' file, if not available use empty file. (default "/etc/snort/sid-msg.map")
  -operation-workers int
        Number of workers used for post-processing of events. Must be >=1. Useful when using TShark to parse packets, as each packet is individually piped to a TShark process, thus increasing value will result in an increased throughput. However, if value is >1, events will be logged/reported out of order. (default 1)
  -report-event-template value
        A go template file to used for printing the events in a report. See '-report-show-event-template' for an example.
  -report-file string
        To enable reporting (i.e. text instead of json) to a file, set to file name. Supports setting to '-' to report to stdout.
  -report-hex-dump
        When set, includes a hex dump of the packet in report.
  -report-packet-template value
        A go template file to used for printing the packets in a report. See '-report-show-packet-template' for an example.
  -report-show-event-template
        When set, prints default event template and quits.
  -report-show-packet-template
        When set, prints default packet template and quits.
  -spooler-base-filename string
        The name of the unified2 files generated by snort (excluding the timestamp). (default "snort.u2")
  -spooler-batch
        Run in batch mode. Read all available records then quit.
  -spooler-directory string
        Specify location where the unified2 log files are written to by snort. (default "/var/log/snort/")
  -spooler-marker value
        File that bookmarks the position of a previous operation (similar to waldo in barnyard). If file does not exist, then program will start from the first file and it will be created on program exit. If value is prefixed with 'marker:' then it will be directly interpreted as the base64 value of the marker, however, it will not be updated on program exit.
  -tshark-filter value
        When performing a full parse with TShark filter the includedlayers in the json to reduce the total size of the log message. The value is passed to TShark by the -J option. Option can be given multiple times, or given a comma separated list. Caution, when processing portscan events it is required to set this to include both 'ip' and 'data' layers. (default ip,data)
  -tshark-level value
        Set level of parsing performed by TShark for captured packets. Full will pass the -P and -V option, summary will pass the -P option and none will disable using tshark. Caution, to correctly process portscan packets, it is required to set this to full. Using full results in a detailed output in the log, whereas the report typically only uses the result of one line summary (if available). (values full, summary, none) (default full)
```

## Sample Report

```
 IDS Event 0:26
------------------
Timestamp: 2019-06-16 10:29:17.078037 +0100 BST
Signature: 19439, Description: "SQL 1 = 1 - possible sql injection attempt"
Classification: "Web Application Attack"
Direction: (tcp) 10.0.0.6:41884 -> 192.168.10.2:80
Action: Was Dropped

 Alert Packet 0:26
---------------------
Event timestamp: 2019-06-16 10:29:17 +0100 BST
Packet timestamp: 2019-06-16 10:29:17.078037 +0100 BST
Summary: "GET /welcome.php?query=x%20or%201%3D1 HTTP/1.1 "
Hash: sha256:d7d75c05bac7a4cf7cb62390eda1014197c7647ed02fcd4d001b7cd464656bef
Raw packet:
00000000  45 00 00 d9 64 3a 40 00  3e 06 03 35 0a 00 00 06  |E...d:@.>..5....|
00000010  c0 a8 0a 02 a3 9c 00 50  56 76 74 02 89 6f 30 79  |.......PVvt..o0y|
00000020  80 18 00 e5 56 5f 00 00  01 01 08 0a ee 98 07 07  |....V_..........|
00000030  9b 44 6d 7b 47 45 54 20  2f 77 65 6c 63 6f 6d 65  |.Dm{GET /welcome|
00000040  2e 70 68 70 3f 71 75 65  72 79 3d 78 25 32 30 6f  |.php?query=x%20o|
00000050  72 25 32 30 31 25 33 44  31 20 48 54 54 50 2f 31  |r%201%3D1 HTTP/1|
00000060  2e 31 0d 0a 48 6f 73 74  3a 20 31 39 32 2e 31 36  |.1..Host: 192.16|
00000070  38 2e 31 30 2e 32 0d 0a  55 73 65 72 2d 41 67 65  |8.10.2..User-Age|
00000080  6e 74 3a 20 63 75 72 6c  2f 37 2e 36 31 2e 31 0d  |nt: curl/7.61.1.|
00000090  0a 41 63 63 65 70 74 3a  20 2a 2f 2a 0d 0a 63 75  |.Accept: */*..cu|
000000a0  73 74 6f 6d 3a 28 29 20  7b 20 3a 3b 20 7d 3b 20  |stom:() { :; }; |
000000b0  2f 75 73 72 2f 62 69 6e  2f 69 64 0d 0a 58 2d 46  |/usr/bin/id..X-F|
000000c0  6f 72 77 61 72 64 65 64  2d 46 6f 72 3a 20 31 2e  |orwarded-For: 1.|
000000d0  31 2e 31 2e 31 0d 0a 0d  0a                       |1.1.1....|
```

### Custom templates

It is possible to customise the reporting format by providing a
[`text/template`][template] template. The uses two templates: one for
the events and one for the packets.

To change the template used for displaying events, first extract the
default template as follows:

```bash
$ u2text -report-show-event-template > event.tmpl
$ cat event.tmpl
 IDS Event {{.Sensor_id}}:{{.Event_id}}
------------------
Timestamp: {{.Event_time.Time}}
{{if eq .Event_info.Generator_id 1 -}} Signature: {{.Event_info.Signature_id}} {{- else -}} Generator: {{.Event_info.Generator_id -}}:{{- .Event_info.Signature_id}} {{- end}}, Description: "{{ with .Event_info.Description }}{{.}}{{else}}---{{end}}"
Classification: {{ with .Classification.Description }}"{{.}}"{{else}}{{.Classification.Id}}{{end}}
Direction: ({{ with .Protocol.Name }}{{.}}{{else}}{{.Protocol.Number}}{{end}}) {{.Ip_source.MarshalText | string}}:{{.Sport_itype}} -> {{.Ip_destination.MarshalText | string}}:{{.Dport_icode}}
Action: {{.Blocked}}
```

Edit `event.tmpl`, then run `u2text` with the following command line
argument:

```bash
$ u2text -report-event-template event.tmpl # ... include other arguments
```

The possible variables that can be used in the template are the same
as those reported in the json log (these can be seen easily by running
the program with `-log-file -` to also print the json objects to the
terminal).

In the case of captured packets that parsed by TShark, its possible to
include any of the fields that are present in a standard Wireshark
dissection in the report. See next section for example log entries.

### Sample Log Entries

Event log entry:

```json
{
  "Sensor_id": 0,
  "Event_id": 26,
  "Event_time": {
    "Second": 1560677357,
    "Microsecond": 78037,
    "Time": "2019-06-16T10:29:17.078037+01:00"
  },
  "Event_info": {
    "Signature_id": 19439,
    "Generator_id": 1,
    "Description": "SQL 1 = 1 - possible sql injection attempt",
    "References": [
      "url,attack.mitre.org/techniques/T1190",
      "url,ferruh.mavituna.com/sql-injection-cheatsheet-oku/"
    ]
  },
  "Signature_revision": 10,
  "Classification": {
    "Id": 28,
    "Name": "web-application-attack",
    "Description": "Web Application Attack"
  },
  "Priority_id": 1,
  "Ip_source": "10.0.0.6",
  "Ip_destination": "192.168.10.2",
  "Sport_itype": 41884,
  "Dport_icode": 80,
  "Protocol": {
    "Number": 6,
    "Name": "tcp"
  },
  "Impact_flag": 32,
  "Impact": 0,
  "Blocked": "Was Dropped"
}
```

Packet log entry:

```json
{
  "Sensor_id": 0,
  "Event_id": 26,
  "Event_second": 1560677357,
  "Packet_time": {
    "Second": 1560677357,
    "Microsecond": 78037,
    "Time": "2019-06-16T10:29:17.078037+01:00"
  },
  "Linktype": 228,
  "Packet_length": 217,
  "Packet_hash": "sha256:d7d75c05bac7a4cf7cb62390eda1014197c7647ed02fcd4d001b7cd464656bef",
  "Packet": {
    "destination": "192.168.10.2",
    "info": "GET /welcome.php?query=x%20or%201%3D1 HTTP/1.1 ",
    "layers": {
      "frame": {
        "filtered": "frame"
      },
      "http": {
        "http_http_accept": "*/*",
        "http_http_host": "192.168.10.2",
        "http_http_request": "1",
        "http_http_request_full_uri": "http://192.168.10.2/welcome.php?query=x%20or%201%3D1",
        "http_http_request_line": [
          "Host: 192.168.10.2\r\n",
          "User-Agent: curl/7.61.1\r\n",
          "Accept: */*\r\n",
          "custom:() { :; }; /usr/bin/id\r\n",
          "X-Forwarded-For: 1.1.1.1\r\n"
        ],
        "http_http_request_number": "1",
        "http_http_user_agent": "curl/7.61.1",
        "http_http_x_forwarded_for": "1.1.1.1",
        "http_request_uri_http_request_uri_path": "/welcome.php",
        "http_request_uri_http_request_uri_query": "query=x%20or%201%3D1",
        "http_request_uri_query_http_request_uri_query_parameter": "query=x%20or%201%3D1",
        "http_text": [
          "GET /welcome.php?query=x%20or%201%3D1 HTTP/1.1\\r\\n",
          "\\r\\n"
        ],
        "text__ws_expert": {
          "_ws_expert__ws_expert_group": "33554432",
          "_ws_expert__ws_expert_message": "GET /welcome.php?query=x%20or%201%3D1 HTTP/1.1\\r\\n",
          "_ws_expert__ws_expert_severity": "2097152",
          "_ws_expert_http_chat": ""
        },
        "text_http_request_method": "GET",
        "text_http_request_uri": "/welcome.php?query=x%20or%201%3D1",
        "text_http_request_version": "HTTP/1.1"
      },
      "ip": {
        "ip_dsfield_ip_dsfield_dscp": "0",
        "ip_dsfield_ip_dsfield_ecn": "0",
        "ip_flags_ip_flags_df": "1",
        "ip_flags_ip_flags_mf": "0",
        "ip_flags_ip_flags_rb": "0",
        "ip_flags_ip_frag_offset": "0",
        "ip_ip_addr": [
          "10.0.0.6",
          "192.168.10.2"
        ],
        "ip_ip_checksum": "0x00000335",
        "ip_ip_checksum_status": "2",
        "ip_ip_dsfield": "0x00000000",
        "ip_ip_dst": "192.168.10.2",
        "ip_ip_dst_host": "192.168.10.2",
        "ip_ip_flags": "0x00004000",
        "ip_ip_hdr_len": "20",
        "ip_ip_host": [
          "10.0.0.6",
          "192.168.10.2"
        ],
        "ip_ip_id": "0x0000643a",
        "ip_ip_len": "217",
        "ip_ip_proto": "6",
        "ip_ip_src": "10.0.0.6",
        "ip_ip_src_host": "10.0.0.6",
        "ip_ip_ttl": "62",
        "ip_ip_version": "4"
      },
      "tcp": {
        "tcp_analysis_tcp_analysis_bytes_in_flight": "165",
        "tcp_analysis_tcp_analysis_push_bytes_sent": "165",
        "tcp_flags_tcp_flags_ack": "1",
        "tcp_flags_tcp_flags_cwr": "0",
        "tcp_flags_tcp_flags_ecn": "0",
        "tcp_flags_tcp_flags_fin": "0",
        "tcp_flags_tcp_flags_ns": "0",
        "tcp_flags_tcp_flags_push": "1",
        "tcp_flags_tcp_flags_res": "0",
        "tcp_flags_tcp_flags_reset": "0",
        "tcp_flags_tcp_flags_str": "Â·Â·Â·Â·Â·Â·Â·APÂ·Â·Â·",
        "tcp_flags_tcp_flags_syn": "0",
        "tcp_flags_tcp_flags_urg": "0",
        "tcp_options_nop_tcp_option_kind": [
          "1",
          "1"
        ],
        "tcp_options_tcp_options_nop": [
          "01",
          "01"
        ],
        "tcp_options_tcp_options_timestamp": "08:0a:ee:98:07:07:9b:44:6d:7b",
        "tcp_options_timestamp_tcp_option_kind": "8",
        "tcp_options_timestamp_tcp_option_len": "10",
        "tcp_options_timestamp_tcp_options_timestamp_tsecr": "2604952955",
        "tcp_options_timestamp_tcp_options_timestamp_tsval": "4002940679",
        "tcp_tcp_ack": "1",
        "tcp_tcp_analysis": "",
        "tcp_tcp_checksum": "0x0000565f",
        "tcp_tcp_checksum_status": "2",
        "tcp_tcp_dstport": "80",
        "tcp_tcp_flags": "0x00000018",
        "tcp_tcp_hdr_len": "32",
        "tcp_tcp_len": "165",
        "tcp_tcp_nxtseq": "166",
        "tcp_tcp_options": "01:01:08:0a:ee:98:07:07:9b:44:6d:7b",
        "tcp_tcp_payload": "47:45:54:20:2f:77:65:6c:63:6f:6d:65:2e:70:68:70:3f:71:75:65:72:79:3d:78:25:32:30:6f:72:25:32:30:31:25:33:44:31:20:48:54:54:50:2f:31:2e:31:0d:0a:48:6f:73:74:3a:20:31:39:32:2e:31:36:38:2e:31:30:2e:32:0d:0a:55:73:65:72:2d:41:67:65:6e:74:3a:20:63:75:72:6c:2f:37:2e:36:31:2e:31:0d:0a:41:63:63:65:70:74:3a:20:2a:2f:2a:0d:0a:63:75:73:74:6f:6d:3a:28:29:20:7b:20:3a:3b:20:7d:3b:20:2f:75:73:72:2f:62:69:6e:2f:69:64:0d:0a:58:2d:46:6f:72:77:61:72:64:65:64:2d:46:6f:72:3a:20:31:2e:31:2e:31:2e:31:0d:0a:0d:0a",
        "tcp_tcp_port": [
          "41884",
          "80"
        ],
        "tcp_tcp_seq": "1",
        "tcp_tcp_srcport": "41884",
        "tcp_tcp_stream": "0",
        "tcp_tcp_urgent_pointer": "0",
        "tcp_tcp_window_size": "229",
        "tcp_tcp_window_size_scalefactor": "-1",
        "tcp_tcp_window_size_value": "229",
        "tcp_text": "Timestamps",
        "text_tcp_time_delta": "0.000000000",
        "text_tcp_time_relative": "0.000000000"
      }
    },
    "length": "217",
    "no_": "1",
    "protocol": "HTTP",
    "source": "10.0.0.6",
    "time": "0.000000",
    "timestamp": "1560677357078"
  }
}
```

## Other Bits

Licensed under GPLv3, Copyright 2019, Karim Kanso, All rights reserved.

[snort]: https://www.snort.org/ "Snort.org: Snort - Network Intrusion Detection & Prevention System"
[gelf]: http://docs.graylog.org/en/3.0/pages/gelf.html "Graylog.org: GELF — Graylog 3.0.0 documentation"
[barnyard2]: https://github.com/firnsy/barnyard2 "GitHub.com: Barnyard2 is a dedicated spooler for Snort's unified2 binary output format."
[sguil]: https://bammv.github.io/sguil/ "Sguil: The Analyst Console for Network Security Monitoring"
[template]: https://golang.org/pkg/text/template/ "Golang.org: template - The Go Programming Language"
[tshark]: https://www.wireshark.org/docs/man-pages/tshark.html "WireShark.org: tshark - The Wireshark Network Analyzer 3.0.2"
[graylog]: https://www.graylog.org/ "Industry Leading Log Management | Graylog"
[parser]: https://godoc.org/github.com/kazkansouh/u2text/parser "parser - GoDoc"
[u2]: https://godoc.org/github.com/kazkansouh/u2text/parser/u2 "u2 - GoDoc"
[spooler]: https://godoc.org/github.com/kazkansouh/u2text/spooler "spooler - GoDoc"
