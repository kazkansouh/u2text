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
	"log"
	"net"
	"path/filepath"
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
Hash: {{.}}{{end}}{{if gt (len .Packet_data) 0}}
Raw packet:
{{.Packet_data | hexdump}}{{end}}
`
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
			return time.Unix(int64(seconds), 0)
		},
		"hexdump": hex.Dump,
	}
)

func init() {
	evt := template.New("event")
	evt.Funcs(funcmap)
	if _, err := evt.Parse(EventTemplate); err != nil {
		log.Fatal("Unable to initialise template: ", err.Error())
	}
	templates["event"] = evt

	pkt := template.New("packet")
	pkt.Funcs(funcmap)
	if _, err := pkt.Parse(PacketTemplate); err != nil {
		log.Fatal("Unable to initialise template: ", err.Error())
	}
	templates["packet"] = pkt

}

// Load a text/template file for report printing of unified2 events
func LoadEventTemplate(file string) error {
	evt := template.New(filepath.Base(file))
	evt.Funcs(funcmap)
	if _, err := evt.ParseFiles(file); err != nil {
		return err
	}
	templates["event"] = evt
	return nil
}

// Load a text/template file for report printing of unified2 packets
func LoadPacketTemplate(file string) error {
	pkt := template.New(filepath.Base(file))
	pkt.Funcs(funcmap)
	if _, err := pkt.ParseFiles(file); err != nil {
		return err
	}
	templates["packet"] = pkt
	return nil
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

func writeTo(x interface{}, template string, w io.Writer) (int64, error) {
	t, ok := templates[template]
	if !ok {
		return 0, errors.New("Template has not been initialised")
	}

	// buffer output to ensure consistent
	buffer := bytes.Buffer{}

	err := t.Execute(&buffer, x)
	if err != nil {
		return 0, err
	}

	i, err := w.Write(buffer.Bytes())
	return int64(i), err
}

// Pretty print event record in a report format
func (x *Unified2IDSEvent_legacy) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", w)
}

// Pretty print event record in a report format
func (x *Unified2IDSEventIPv6_legacy) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", w)
}

// Pretty print event record in a report format
func (x *Unified2IDSEvent) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", w)
}

// Pretty print event record in a report format
func (x *Unified2IDSEventIPv6) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "event", w)
}

// Pretty print packet
func (x *Unified2Packet) WriteTo(w io.Writer) (int64, error) {
	return writeTo(x, "packet", w)
}

// Decode packet using TShark and store result in the Packet
// field. Subsequent calls overwrite the result.
func (x *Unified2Packet) DecodePacket(onlySummary bool, fullParseFilter []string) error {
	args := []string{"-P"}
	if !onlySummary {
		args = append(args, "-V")
		if len(fullParseFilter) > 0 {
			args = append(args, "-J", strings.Join(fullParseFilter, " "))
		}

	}
	pkt, err := packet.ParsePacket(
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
	if onlySummary {
		return nil
	}

	// First, check protocol ip is 255.
	// { "layers" : {"ip" : {"ip_ip_proto" : "255"} }
	// "layers" is only included with "-V" option
	layers_interface, ok := pkt["layers"]
	if !ok {
		return nil
	}
	layers, ok := layers_interface.(map[string]interface{})
	if !ok {
		return nil
	}
	ip_interface, ok := layers["ip"]
	if !ok {
		return nil
	}
	ip, ok := ip_interface.(map[string]interface{})
	if !ok {
		return nil
	}
	protocol, ok := ip["ip_ip_proto"]
	if !ok {
		return nil
	}
	if protocol != "255" {
		return nil
	}

	// Secondly, access ip payload, if present
	// { "layers" : {"data" : {"data_data_data" : "xx:xx:xx"} }
	data_interface, ok := layers["data"]
	if !ok {
		return nil
	}
	data, ok := data_interface.(map[string]interface{})
	if !ok {
		return nil
	}
	ip_data, ok := data["data_data_data"]
	if !ok {
		return nil
	}
	payload, ok := ip_data.(string)
	if !ok {
		log.Println("WARNING: string expected in data_data_data")
		return nil
	}

	// Finally decode and save payload into
	// { "info" : ... }
	message, err := hex.DecodeString(strings.Replace(payload, ":", "", -1))
	if err != nil {
		return err
	}
	pkt["info"] = string(message)
	return nil
}

// Calculate hash of packet data and store into Packet_hash field of
// Unified2Packet
func (x *Unified2Packet) CalculateHash() {
	hash := sha256.Sum256(x.packet_data)
	x.Packet_hash = "sha256:" + hex.EncodeToString(hash[:])
}
