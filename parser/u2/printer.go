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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"text/template"
	"time"

	"github.com/kazkansouh/u2text/parser/packet"
)

const (
	EventTemplate = `
 IDS Event {{.Sensor_id}}:{{.Event_id}}
------------------
Timestamp: {{.Event_time.Time}}
{{if eq .Event_info.Generator_id 1 -}} Signature: {{.Event_info.Signature_id}} {{- else -}} Generator: {{.Event_info.Generator_id -}}:{{- .Event_info.Signature_id}} {{- end}}, Description: "{{ with .Event_info.Description }}{{.}}{{else}}---{{end}}"
Classification: {{ with .Classification.Description }}"{{.}}"{{else}}{{.Classification.Id}}{{end}}
Direction: ({{ with .Protocol.Name }}{{.}}{{else}}{{.Protocol.Number}}{{end}}) {{.Ip_source.MarshalText | string}}:{{.Sport_itype}} -> {{.Ip_destination.MarshalText | string}}:{{.Dport_icode}}
Action: {{.Blocked}}
`
	PacketTemplate = `
 Alert Packet {{.Sensor_id}}:{{.Event_id}}
---------------------
Event timestamp: {{.Event_second | time}}
Packet timestamp: {{.Packet_time.Time}}{{with index .Packet "info"}}
Summary: "{{.}}"{{end}}{{with .Packet_hash}}
Hash: {{.}}{{end}}
Packet len: {{.Packet_length}}{{if gt (len .Packet_data) 0}}
Raw packet:
{{.Packet_data | hexdump}}{{else}}
{{end}}`
)

var (
	templates = map[string]*template.Template{}
	funcmap   = template.FuncMap{
		"string": func(s interface{}) (string, error) {
			switch v := s.(type) {
			case []byte:
				return string(v), nil
			default:
				return "", errors.New("Can not convert to string")
			}
		},
		"time": func(seconds uint32) time.Time {
			return time.Unix(int64(seconds), 0).In(time.UTC)
		},
		"hexdump": hex.Dump,
	}
)

// load a template from string
func loadTemplate(name, tmplText string) (*template.Template, error) {
	tmpl := template.New(name)
	tmpl.Funcs(funcmap)
	if _, err := tmpl.Parse(tmplText); err != nil {
		return nil, err
	}
	templates[name] = tmpl
	return tmpl, nil
}

// Load a text/template file for report printing of unified2 events
func LoadEventTemplate(file string) error {
	buff, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	_, err = loadTemplate("event", string(buff))
	return err
}

// Load a text/template file for report printing of unified2 packets
func LoadPacketTemplate(file string) error {
	buff, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	_, err = loadTemplate("packet", string(buff))
	return err
}

func (s *EventID) Description() string {
	if s.mmap != nil {
		if s.Generator_id == 1 {
			if msg, ok := s.mmap.S[s.Signature_id]; ok {
				return msg.Description
			}
		} else {
			if alerts, ok := s.mmap.G[s.Generator_id]; ok {
				if msg, ok := alerts[s.Signature_id]; ok {
					return msg.Description
				}
			}
		}
	}
	return ""
}

func (s *EventID) References() []string {
	if s.mmap != nil {
		if s.Generator_id == 1 {
			if msg, ok := s.mmap.S[s.Signature_id]; ok {
				return msg.References
			}
		}
	}
	return []string{}
}

func (s EventID) MarshalJSON() ([]byte, error) {
	r := struct {
		Signature_id uint32
		Generator_id uint32
		Description  string   `json:",omitempty"`
		References   []string `json:",omitempty"`
	}{
		Signature_id: s.Signature_id,
		Generator_id: s.Generator_id,
		Description:  s.Description(),
		References:   s.References(),
	}

	return json.Marshal(r)
}

// Lookup the protocol name from the number in the map
func (s *Protocol) Name() string {
	if s.mmap != nil {
		if protocol, ok := s.mmap.P[s.Number]; ok {
			return protocol
		}
	}
	return ""
}

func (s Protocol) MarshalJSON() ([]byte, error) {
	r := struct {
		Number uint8
		Name   string `json:",omitempty"`
	}{
		Number: s.Number,
		Name:   s.Name(),
	}

	return json.Marshal(r)
}

// Lookup classification name
func (s *Classification) Name() string {
	if s.mmap != nil {
		if class, ok := s.mmap.C[s.Id]; ok {
			return class.Name
		}
	}
	return ""
}

// Lookup classification description
func (s *Classification) Description() string {
	if s.mmap != nil {
		if class, ok := s.mmap.C[s.Id]; ok {
			return class.Description
		}
	}
	return ""
}

// Add name and description fields into json object
func (s Classification) MarshalJSON() ([]byte, error) {
	r := struct {
		Id          uint32
		Name        string `json:",omitempty"`
		Description string `json:",omitempty"`
	}{
		Id:          s.Id,
		Name:        s.Name(),
		Description: s.Description(),
	}

	return json.Marshal(r)
}

// Lift underlying pretty print function
func (ip IPv4) MarshalText() ([]byte, error) {
	return net.IP(ip).MarshalText()
}

// Lift underlying pretty print function
func (ip IPv6) MarshalText() ([]byte, error) {
	return net.IP(ip).MarshalText()
}

func lookupTemplate(template string, fallback string) (*template.Template, error) {
	t, ok := templates[template]
	if !ok {
		return loadTemplate(template, fallback)
	}
	return t, nil

}

func writeTo(x interface{}, template string, fallback string, w io.Writer) (int64, error) {
	// get a template
	t, err := lookupTemplate(template, fallback)
	if err != nil {
		return 0, err
	}

	// buffer output to ensure consistent
	buffer := bytes.Buffer{}

	err = t.Execute(&buffer, x)
	if err != nil {
		return 0, err
	}

	i, err := w.Write(buffer.Bytes())
	return int64(i), err
}

// Pretty print event record in a report format
func (x *Unified2IDSEvent_legacy) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", EventTemplate, w)
}

// Pretty print event record in a report format
func (x *Unified2IDSEventIPv6_legacy) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", EventTemplate, w)
}

// Pretty print event record in a report format
func (x *Unified2IDSEvent) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", EventTemplate, w)
}

// Pretty print event record in a report format
func (x *Unified2IDSEventIPv6) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", EventTemplate, w)
}

// Pretty print packet
func (x *Unified2Packet) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "packet", PacketTemplate, w)
}

// lookup in a hierarchy of maps a given value, if it exists,
// otherwise return nil
func findVal(m map[string]interface{}, path []string) interface{} {
	var v interface{} = m
	for _, p := range path {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v, ok = m[p]
		if !ok {
			return nil
		}
	}
	return v
}

// Decode packet using TShark and store result in the Packet
// field. Subsequent calls overwrite the result.
func (x *Unified2Packet) DecodePacket(onlySummary bool, fullParseFilter []string) error {
	return x.decodePacket(packet.ParsePacket, onlySummary, fullParseFilter)
}

type decoder func(uint32, uint32, uint32, []byte, []string) (map[string]interface{}, error)

// Decode packet using TShark and store result in the Packet
// field. Subsequent calls overwrite the result.
func (x *Unified2Packet) decodePacket(
	decoder decoder,
	onlySummary bool,
	fullParseFilter []string,
) error {
	args := []string{"-P"}
	if !onlySummary {
		args = append(args, "-V")
		if len(fullParseFilter) > 0 {
			args = append(args, "-J", strings.Join(fullParseFilter, " "))
		}

	}
	pkt, err := decoder(
		x.Packet_time.Second,
		x.Packet_time.Microsecond,
		x.Linktype,
		x.packet_data,
		args)
	if err != nil {
		return err
	}
	x.Packet = pkt

	// If packet is the result of sfPortscan, parse the payload
	// and place into the info field. Relies on TShark to parse
	// packet, thus only works if "-T ek -V" has been passed to
	// TShark. If a filter has been used, then it must have
	// included "ip data" otherwise the below will not work.

	// First, check protocol ip is 255.
	// { "layers" : {"ip" : {"ip_ip_proto" : "255"} }
	// "layers" is only included with "-V" option
	if protocol, ok := findVal(x.Packet, []string{"layers", "ip", "ip_ip_proto"}).(string); !ok || protocol != "255" {
		return nil
	}

	// Secondly, access ip payload, if present
	// { "layers" : {"data" : {"data_data_data" : "xx:xx:xx"} }
	if data, ok := findVal(x.Packet, []string{"layers", "data", "data_data_data"}).(string); ok {
		// Finally decode and save payload into
		// { "info" : ... }
		message, err := hex.DecodeString(strings.Replace(data, ":", "", -1))
		if err != nil {
			return err
		}
		x.Packet["info"] = string(message)
	}
	return nil
}

// Calculate hash of packet data and store into Packet_hash field of
// Unified2Packet
func (x *Unified2Packet) CalculateHash() {
	hash := sha256.Sum256(x.packet_data)
	x.Packet_hash = "sha256:" + hex.EncodeToString(hash[:])
}
