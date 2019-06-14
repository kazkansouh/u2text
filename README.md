# Unified2 log parser for Go - u2text

I wrote this code primarily as a tool with a functional and clean
interface that has a small number of runtime dependencies to
post-process the [Snort][snort] unified2 log files in a lab
environment. While setting up a lab, I became frustrated with other
tools that I tried as many are becoming dated/un-maintained
(i.e. implies compatibility issues) and none of the ones I tried
satisfactorily provided both a clean text output (as I typically run
snort within Docker its something that is useful for quick tests) as
well as logging to a remote server in a meaningful way (e.g. ability
to control full packet captures).

There are other tools such as [*Sguil*][sguil] which are much holistic
in scope. Thus, this code should be seen as something analogous to
[*barnyard2*][barnyard2] tuned to my requirements (and modernised).

The following features are present:

* Support for using TShark (command line version of WireShark) to
  parse packet captures before sending to logging server.
    * Multiple levels:
        1. `none`: do not use TShark
        2. `summary`: generate a one line summary of the packet
           (similar to what WireShark will show).
        3. `full`: Apply the standard dissectors to the packet to
           obtain a JSON object. See `-T ek -P -V` options for TShark.

            To reduce the size of information sent to the logging server,
            it possible to filter the layers included in the output. See
            the `-J` option for TShark.
* Support for interpreting `sfPortscan` payloads (see the *Snort*
  manual). Requires that `u2text` is run with TShark at the `full`
  level and at minimum the `ip` and `data` layers are no filtered.
* Support for parsing the `sid-msg.map`, `gen-msg.map` and
  `classification.config` files to translate numeric values into
  textual values.
* Support for logging JSON via [GELF][gelf] (UDP), Syslog or to a
  local file. It is recommended to use GELF as it supports larger
  messages than Syslog.
* Text based report that can be output to either the terminal or a
  file.
    * Possible to provide custom templates to change the report format.
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

## Sample Report

```
 IDS Event 0:1
------------------
Timestamp: 2019-06-13 11:09:06.011146 +0100 BST
Signature: 19439, Description: "SQL 1 = 1 - possible sql injection attempt"
Classification: "Web Application Attack"
Direction: (tcp) 10.0.0.6:41920 -> 192.168.10.2:80
Action: Was Dropped

 Alert Packet 0:1
---------------------
Event timestamp: 2019-06-13 11:09:06 +0100 BST
Packet timestamp: 2019-06-13 11:09:06.011146 +0100 BST
Hash: sha256:43d8fc7302afe8ca0bd6ae2fa21e39cd9c964075d4565db9f3ca6139f7a5a54d
Raw packet:
00000000  45 00 00 b7 20 f3 40 00  3e 06 46 9e 0a 00 00 06  |E... .@.>.F.....|
00000010  c0 a8 0a 02 a3 c0 00 50  d9 1c 62 9d 94 5d 1a 6f  |.......P..b..].o|
00000020  80 18 00 e5 f9 ce 00 00  01 01 08 0a ea 44 d1 c1  |.............D..|
00000030  96 f1 38 34 47 45 54 20  2f 77 65 6c 63 6f 6d 65  |..84GET /welcome|
00000040  2e 70 68 70 3f 71 75 65  72 79 3d 78 25 32 30 6f  |.php?query=x%20o|
00000050  72 25 32 30 31 25 33 44  31 20 48 54 54 50 2f 31  |r%201%3D1 HTTP/1|
00000060  2e 31 0d 0a 48 6f 73 74  3a 20 62 69 67 77 69 6c  |.1..Host: bigwil|
00000070  6c 69 65 0d 0a 55 73 65  72 2d 41 67 65 6e 74 3a  |lie..User-Agent:|
00000080  20 63 75 72 6c 2f 37 2e  36 31 2e 31 0d 0a 41 63  | curl/7.61.1..Ac|
00000090  63 65 70 74 3a 20 2a 2f  2a 0d 0a 58 2d 46 6f 72  |cept: */*..X-For|
000000a0  77 61 72 64 65 64 2d 46  6f 72 3a 20 31 2e 31 2e  |warded-For: 1.1.|
000000b0  31 2e 31 0d 0a 0d 0a                              |1.1....|
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
the program with `-log-file -` to also print the json objects).

In the case of captured packets that parsed by TShark, its possible to
include any of the fields that are present in a standard Wireshark
dissection in the report.

## Usage

The program is available in the standard `go` way:

```
go get github.com/kazkansouh/u2text
```

The sub-packages of the program can be taken to parse the unified2
files independently. That is, the `parser/u2` package has all the code
needed to parse a single unified2 file and the `spooler` package has
all the code to track multiple unified2 files.

The following options are available:

```
$ u2text  -help
Usage of u2text:
  -gelf string
        To enable gelf logging, set to server address in the format 'address:port'. Only supports UDP.
  -log-displaypacket value
        Select whether to include full packet capture in the log or only a sha256 hash. Option can be used to reduce the size of logs sent to server. Note, when set to hash, will also include hash in report. (values full, hash) (default hash)
  -log-file string
        To enable logging locally to a file, set to file name. Supports setting to '-' to log to stdout.
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
  -syslog string
        To enable syslog logging, set to server address in the format 'protocol://address:port'. Where protocol is 'tcp' or 'udp'. To log to local syslogd, set to 'localhost'.
  -tshark-filter value
        When performing a full parse with TShark filter the includedlayers in the json to reduce the total size of the log message. The value is passed to TShark by the -J option. Option can be given multiple times, or given a comma separated list. Caution, when processing portscan events it is required to set this to include both 'ip' and 'data' layers. (default ip,data)
  -tshark-level value
        Set level of parsing performed by TShark for captured packets. Full will pass the -P and -V option, summary will pass the -P option and none will disable using tshark. Caution, to correctly process portscan packets, it is required to set this to full. Using full results in a detailed output in the log, whereas the report typically only uses the result of one line summary (if available). (values full, summary, none) (default full)
```

# Other Bits

Licensed under GPLv3, Copyright 2019, Karim Kanso, All rights reserved.

[snort]: https://www.snort.org/ "Snort.org: Snort - Network Intrusion Detection & Prevention System"
[gelf]: http://docs.graylog.org/en/3.0/pages/gelf.html "Graylog.org: GELF — Graylog 3.0.0 documentation"
[barnyard2]: https://github.com/firnsy/barnyard2 "GitHub.com: Barnyard2 is a dedicated spooler for Snort's unified2 binary output format."
[sguil]: https://bammv.github.io/sguil/ "Sguil: The Analyst Console for Network Security Monitoring"
[template]: https://golang.org/pkg/text/template/ "Golang.org: template - The Go Programming Language"
[tshark]: https://www.wireshark.org/docs/man-pages/tshark.html "WireShark.org: tshark - The Wireshark Network Analyzer 3.0.2"
[graylog]: https://www.graylog.org/ "Industry Leading Log Management | Graylog"
