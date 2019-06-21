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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"text/template"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"

	"github.com/google/go-cmp/cmp"

	"github.com/kazkansouh/u2text/parser/classification"
	"github.com/kazkansouh/u2text/parser/gen"
	"github.com/kazkansouh/u2text/parser/protocol"
	"github.com/kazkansouh/u2text/parser/sid"
)

func TestLoadTemplate(t *testing.T) {

	type test struct {
		tmpl    string
		pass    bool
		f       func(string) error
		errtest func(error) bool
	}

	tests := []test{
		test{"event", false, LoadEventTemplate, nil},
		test{"packet", false, LoadPacketTemplate, nil},
		test{"event", true, LoadEventTemplate, nil},
		test{"packet", true, LoadPacketTemplate, nil},
		test{"nofile", false, LoadEventTemplate, os.IsNotExist},
		test{"nofile", false, LoadPacketTemplate, os.IsNotExist},
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			name := fmt.Sprintf("testdata/%s.tmpl.%t", test.tmpl, test.pass)

			switch {
			case test.pass:
				assert.NilError(t, test.f(name), name)
			case test.errtest != nil:
				assert.ErrorType(t, test.f(name), test.errtest)
			default:
				assert.ErrorContains(t, test.f(name), "template: "+test.tmpl, name)
			}
		}
	}

	// output internal templates to file as test inputs
	assert.NilError(t, ioutil.WriteFile("testdata/event.tmpl.true", []byte(EventTemplate), 0644))
	assert.NilError(t, ioutil.WriteFile("testdata/packet.tmpl.true", []byte(PacketTemplate), 0644))

	for _, test := range tests {
		t.Run(fmt.Sprintf("%s-%t", test.tmpl, test.pass), testfunc(&test))
	}
}

var (
	aTime = Time{
		Second:      1560850942,
		Microsecond: 123321,
		Time:        time.Unix(1560850942, 123321000).In(time.UTC),
	}

	aGeneratorEvent = EventID{
		Signature_id: 1,
		Generator_id: 2,
	}

	aSignatureEvent = EventID{
		Signature_id: 2,
		Generator_id: 1,
	}

	aClassification = Classification{
		Id: 28,
	}

	aProtocol = Protocol{
		Number: 6,
	}

	anIPv4_Astr = "192.0.2.1"
	anIPv4_A    = IPv4(net.ParseIP(anIPv4_Astr))
	anIPv4_Bstr = "192.0.2.255"
	anIPv4_B    = IPv4(net.ParseIP(anIPv4_Bstr))

	anIPv6_Astr = "2001:db8::1"
	anIPv6_A    = IPv6(net.ParseIP(anIPv6_Astr))
	anIPv6_Bstr = "2001:db8::ff"
	anIPv6_B    = IPv6(net.ParseIP(anIPv6_Bstr))

	aMap = &MessageMap{
		G: gen.GenMap{2: map[uint32]*gen.GEN{1: &gen.GEN{Description: "Generator"}}},
		S: sid.SidMap{2: &sid.SID{Description: "Signature", References: []string{"ref1", "ref2"}}},
		P: protocol.ProtocolMap{6: "tcp"},
		C: classification.ClassMap{28: &classification.Classification{Name: "Class", Description: "Classification", Priority: 1}},
	}
)

func TestEvent_Print(t *testing.T) {

	type test struct {
		name       string
		obj        io.WriterTo
		fields     map[string]interface{}
		mmap       *MessageMap
		generator  func(t *testing.T, obj io.WriterTo) ([]byte, error)
		expected   string
		arguments  []interface{}
		comparator func(t *testing.T, expected, actual []byte)
	}

	testfunc := func(test *test) func(t *testing.T) {
		return func(t *testing.T) {
			// instantiate event
			evt := reflect.ValueOf(test.obj).Elem()
			for k, v := range test.fields {
				if field := evt.FieldByName(k); field.IsValid() {
					field.Set(reflect.ValueOf(v))
				} else {
					t.Fatal("Missing field", k, "in", reflect.TypeOf(evt))
				}
			}

			// bond event to map
			if mb, ok := test.obj.(MessageBonder); ok && test.mmap != nil {
				mb.BondMessageMap(test.mmap)
			}

			// generate output
			actual_bytes, err := test.generator(t, test.obj)
			assert.NilError(t, err)
			if testing.Verbose() {
				t.Log(string(actual_bytes))
			}

			// prepare expected
			expected_str := fmt.Sprintf(test.expected, test.arguments...)

			// compare with expected
			test.comparator(t, []byte(expected_str), actual_bytes)
		}
	}

	fields_v4 := map[string]interface{}{
		"Sensor_id":          uint32(1),
		"Event_id":           uint32(2),
		"Event_time":         aTime,
		"Event_info":         aGeneratorEvent,
		"Signature_revision": uint32(3),
		"Classification":     aClassification,
		"Priority_id":        uint32(4),
		"Ip_source":          anIPv4_A,
		"Ip_destination":     anIPv4_B,
		"Sport_itype":        uint16(5),
		"Dport_icode":        uint16(6),
		"Protocol":           aProtocol,
		"Impact_flag":        uint8(32),
		"Blocked":            Blocked("Was Dropped"),
	}

	fields_v6 := map[string]interface{}{}
	for k, v := range fields_v4 {
		fields_v6[k] = v
	}
	fields_v6["Ip_source"] = anIPv6_A
	fields_v6["Ip_destination"] = anIPv6_B

	fields_v4s := map[string]interface{}{}
	for k, v := range fields_v4 {
		fields_v4s[k] = v
	}
	fields_v4s["Event_info"] = aSignatureEvent

	json_expected_plain := `
{
   "Priority_id" : 4,
   "Sensor_id" : 1,
   "Blocked" : "Was Dropped",
   "Classification" : {
      "Id" : 28
   },
   "Sport_itype" : 5,
   "Event_time" : {
      "Microsecond" : 123321,
      "Second" : 1560850942,
      "Time" : "2019-06-18T09:42:22.123321Z"
   },
   "Event_info" : {
      "Generator_id" : 2,
      "Signature_id" : 1
   },
   "Dport_icode" : 6,
   "Impact" : 0,
   "Impact_flag" : 32,
   "Protocol" : {
      "Number" : 6
   },
   "Ip_destination" : "%s",
   "Ip_source" : "%s",
   "Event_id" : 2,
   "Signature_revision" : 3
}
`

	json_expected_mapped := `
{
   "Priority_id" : 4,
   "Sensor_id" : 1,
   "Blocked" : "Was Dropped",
   "Classification" : {
      "Id" : 28,
      "Name" : "Class",
      "Description" : "Classification"
   },
   "Sport_itype" : 5,
   "Event_time" : {
      "Microsecond" : 123321,
      "Second" : 1560850942,
      "Time" : "2019-06-18T09:42:22.123321Z"
   },
   "Event_info" : {
      "Generator_id" : %d,
      "Signature_id" : %d,
      "Description" : "%s"%s
   },
   "Dport_icode" : 6,
   "Impact" : 0,
   "Impact_flag" : 32,
   "Protocol" : {
      "Name" : "tcp",
      "Number" : 6
   },
   "Ip_destination" : "%s",
   "Ip_source" : "%s",
   "Event_id" : 2,
   "Signature_revision" : 3
}
`

	report_expected_plain := `
 IDS Event 1:2
------------------
Timestamp: 2019-06-18 09:42:22.123321 +0000 UTC
Generator: 2:1, Description: "---"
Classification: 28
Direction: (6) %s:5 -> %s:6
Action: Was Dropped
`

	json_gen := func(t *testing.T, obj io.WriterTo) ([]byte, error) {
		return json.Marshal(obj)
	}

	json_comp := func(t *testing.T, expected_bytes, actual_bytes []byte) {
		var expected interface{}
		assert.NilError(t, json.Unmarshal(expected_bytes, &expected))
		var actual interface{}
		assert.NilError(t, json.Unmarshal(actual_bytes, &actual))

		assert.DeepEqual(t, expected, actual)
	}

	report_gen := func(t *testing.T, obj io.WriterTo) ([]byte, error) {
		buff := bytes.Buffer{}
		n, err := obj.WriteTo(&buff)
		assert.Equal(t, n, int64(buff.Len()))
		return buff.Bytes(), err
	}

	report_comp := func(t *testing.T, expected_bytes, actual_bytes []byte) {
		assert.DeepEqual(t, expected_bytes, actual_bytes)
	}

	tests := []test{
		test{
			name:       "Unified2IDSEvent_legacy-json",
			obj:        &Unified2IDSEvent_legacy{},
			fields:     fields_v4,
			mmap:       nil,
			generator:  json_gen,
			expected:   json_expected_plain,
			arguments:  []interface{}{anIPv4_Bstr, anIPv4_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEvent-json",
			obj:        &Unified2IDSEvent{},
			fields:     fields_v4,
			mmap:       nil,
			generator:  json_gen,
			expected:   json_expected_plain,
			arguments:  []interface{}{anIPv4_Bstr, anIPv4_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEventIPv6_legacy-json",
			obj:        &Unified2IDSEventIPv6_legacy{},
			fields:     fields_v6,
			mmap:       nil,
			generator:  json_gen,
			expected:   json_expected_plain,
			arguments:  []interface{}{anIPv6_Bstr, anIPv6_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEventIPv6-json",
			obj:        &Unified2IDSEventIPv6{},
			fields:     fields_v6,
			mmap:       nil,
			generator:  json_gen,
			expected:   json_expected_plain,
			arguments:  []interface{}{anIPv6_Bstr, anIPv6_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEvent_legacy-report",
			obj:        &Unified2IDSEvent_legacy{},
			fields:     fields_v4,
			mmap:       nil,
			generator:  report_gen,
			expected:   report_expected_plain,
			arguments:  []interface{}{anIPv4_Astr, anIPv4_Bstr},
			comparator: report_comp,
		},
		test{
			name:       "Unified2IDSEvent-report",
			obj:        &Unified2IDSEvent{},
			fields:     fields_v4,
			mmap:       nil,
			generator:  report_gen,
			expected:   report_expected_plain,
			arguments:  []interface{}{anIPv4_Astr, anIPv4_Bstr},
			comparator: report_comp,
		},
		test{
			name:       "Unified2IDSEventIPv6_legacy-report",
			obj:        &Unified2IDSEventIPv6_legacy{},
			fields:     fields_v6,
			mmap:       nil,
			generator:  report_gen,
			expected:   report_expected_plain,
			arguments:  []interface{}{anIPv6_Astr, anIPv6_Bstr},
			comparator: report_comp,
		},
		test{
			name:       "Unified2IDSEventIPv6-report",
			obj:        &Unified2IDSEventIPv6{},
			fields:     fields_v6,
			mmap:       nil,
			generator:  report_gen,
			expected:   report_expected_plain,
			arguments:  []interface{}{anIPv6_Astr, anIPv6_Bstr},
			comparator: report_comp,
		},
		test{
			name:       "Unified2IDSEvent_legacy-json+mapped",
			obj:        &Unified2IDSEvent_legacy{},
			fields:     fields_v4,
			mmap:       aMap,
			generator:  json_gen,
			expected:   json_expected_mapped,
			arguments:  []interface{}{2, 1, "Generator", "", anIPv4_Bstr, anIPv4_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEvent-json+mapped",
			obj:        &Unified2IDSEvent{},
			fields:     fields_v4,
			mmap:       aMap,
			generator:  json_gen,
			expected:   json_expected_mapped,
			arguments:  []interface{}{2, 1, "Generator", "", anIPv4_Bstr, anIPv4_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEventIPv6_legacy-json+mapped",
			obj:        &Unified2IDSEventIPv6_legacy{},
			fields:     fields_v6,
			mmap:       aMap,
			generator:  json_gen,
			expected:   json_expected_mapped,
			arguments:  []interface{}{2, 1, "Generator", "", anIPv6_Bstr, anIPv6_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEventIPv6-json+mapped",
			obj:        &Unified2IDSEventIPv6{},
			fields:     fields_v6,
			mmap:       aMap,
			generator:  json_gen,
			expected:   json_expected_mapped,
			arguments:  []interface{}{2, 1, "Generator", "", anIPv6_Bstr, anIPv6_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEvent_legacy(sig)-json+mapped",
			obj:        &Unified2IDSEvent_legacy{},
			fields:     fields_v4s,
			mmap:       aMap,
			generator:  json_gen,
			expected:   json_expected_mapped,
			arguments:  []interface{}{1, 2, "Signature", `, "References": ["ref1", "ref2"]`, anIPv4_Bstr, anIPv4_Astr},
			comparator: json_comp,
		},
		test{
			name:       "Unified2IDSEvent(sig)-json+mapped",
			obj:        &Unified2IDSEvent{},
			fields:     fields_v4s,
			mmap:       aMap,
			generator:  json_gen,
			expected:   json_expected_mapped,
			arguments:  []interface{}{1, 2, "Signature", `, "References": ["ref1", "ref2"]`, anIPv4_Bstr, anIPv4_Astr},
			comparator: json_comp,
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestBadTemplate(t *testing.T) {
	name := "testdata/event.tmpl.missingvar"
	assert.NilError(t, LoadEventTemplate(name))
	defer LoadEventTemplate("testdata/event.tmpl.true")

	evt := Unified2IDSEvent_legacy{}
	buff := bytes.Buffer{}
	n, err := evt.WriteTo(&buff)
	assert.Equal(t, n, int64(0))
	assert.ErrorContains(t, err, "DescriptionX")
}

func TestPacket_Print(t *testing.T) {

	newPkt := func(packet_data []byte, packet_uri string) *Unified2Packet {
		return &Unified2Packet{
			Sensor_id:     1,
			Event_id:      2,
			Event_second:  aTime.Second,
			Packet_time:   aTime,
			Linktype:      228, // DLT_IPV4
			Packet_length: uint32(len(packet_data)),
			Packet_data:   packet_data,
			packet_data:   packet_data,
			Packet_uri:    packet_uri,
		}
	}

	type test struct {
		name          string
		packet_data   []byte
		packet_uri    string
		decode        bool
		decode_filter []string
		hash          bool
		generator     func(t *testing.T, obj *Unified2Packet) ([]byte, error)
		expected      string
		arguments     []interface{}
		comparator    func(t *testing.T, expected, actual []byte)
	}

	testfunc := func(test *test) func(t *testing.T) {
		return func(t *testing.T) {
			// instantiate packet
			pkt := newPkt(test.packet_data, test.packet_uri)

			if test.decode {

				out, err := exec.Command("tshark", "--version").Output()
				if err != nil {
					t.Skip("TShark not working, skipping")
				}
				if testing.Verbose() {
					t.Log("TShark version")
					t.Log(string(out))
				}

				assert.NilError(t, pkt.DecodePacket(test.decode_filter == nil, test.decode_filter))
			}

			if test.hash {
				pkt.CalculateHash()
				pkt.Packet_data = nil
			}

			// generate output
			actual_bytes, err := test.generator(t, pkt)
			assert.NilError(t, err)
			if testing.Verbose() {
				t.Log(string(actual_bytes))
			}

			// prepare expected
			expected_str := fmt.Sprintf(test.expected, test.arguments...)

			// compare with expected
			test.comparator(t, []byte(expected_str), actual_bytes)
		}
	}

	// ipv4 packet of a http request
	packet, err := hex.DecodeString(
		"450000bf420e40003e06257b0a000006c0a80a02c4c60050d9f385bbf447" +
			"1d93801800e5335e00000101080adeaaea2e8b5750a2474554202f77656c" +
			"636f6d652e7068703f71756572793d782532306f72253230312533443120" +
			"485454502f312e310d0a486f73743a203139322e3136382e31302e320d0a" +
			"557365722d4167656e743a206375726c2f372e36312e310d0a4163636570" +
			"743a202a2f2a0d0a637573746f6d3a2829207b203a3b207d3b202f757372" +
			"2f62696e2f69640d0a0d0a")
	assert.NilError(t, err)

	packet_hex := hex.Dump(packet)
	packet_b64 := base64.StdEncoding.EncodeToString(packet)
	_packet_hash := sha256.Sum256(packet)
	packet_hash := hex.EncodeToString(_packet_hash[:])
	packet_summary := "GET /welcome.php?query=x%20or%201%3D1 HTTP/1.1 "

	pscan_packet, err := hex.DecodeString(
		"45000098018540003fff659b0a000006c0a80a025072696f726974792043" +
			"6f756e743a20350a436f6e6e656374696f6e20436f756e743a20350a4950" +
			"20436f756e743a20310a5363616e6e65722049502052616e67653a203130" +
			"2e302e302e363a31302e302e302e360a506f72742f50726f746f20436f75" +
			"6e743a20350a506f72742f50726f746f2052616e67653a2032333a313732" +
			"330a")
	assert.NilError(t, err)
	pscan_packet_hex := hex.Dump(pscan_packet)
	pscan_packet_b64 := base64.StdEncoding.EncodeToString(pscan_packet)
	pscan_packet_summary := `Priority Count: 5
Connection Count: 5
IP Count: 1
Scanner IP Range: 10.0.0.6:10.0.0.6
Port/Proto Count: 5
Port/Proto Range: 23:1723
`

	json_expected_plain := `
{
   "Event_second" : 1560850942,
   "Packet_time" : {
      "Second" : 1560850942,
      "Microsecond" : 123321,
      "Time" : "2019-06-18T09:42:22.123321Z"
   },
   "Packet_length" : %d,
   "Packet_data" : "%s",
   "Sensor_id" : 1,
   "Linktype" : 228,
   "Event_id" : 2
}
`
	report_expected_plain := `
 Alert Packet 1:2
---------------------
Event timestamp: 2019-06-18 09:42:22 +0000 UTC
Packet timestamp: 2019-06-18 09:42:22.123321 +0000 UTC
Packet len: %d
Raw packet:
%s`

	json_expected_hash := `
{
   "Event_second" : 1560850942,
   "Packet_time" : {
      "Second" : 1560850942,
      "Microsecond" : 123321,
      "Time" : "2019-06-18T09:42:22.123321Z"
   },
   "Packet_length" : %d,
   "Packet_hash" : "sha256:%s",
   "Sensor_id" : 1,
   "Linktype" : 228,
   "Event_id" : 2
}
`
	report_expected_hash := `
 Alert Packet 1:2
---------------------
Event timestamp: 2019-06-18 09:42:22 +0000 UTC
Packet timestamp: 2019-06-18 09:42:22.123321 +0000 UTC
Hash: sha256:%s
Packet len: %d
`

	json_expected_summary := `
{
   "Event_second" : 1560850942,
   "Packet_time" : {
      "Second" : 1560850942,
      "Microsecond" : 123321,
      "Time" : "2019-06-18T09:42:22.123321Z"
   },
   "Packet_length" : %d,
   "Packet_data" : "%s",
   "Sensor_id" : 1,
   "Linktype" : 228,
   "Event_id" : 2,
   "Packet" : {
      "timestamp" : "1560850942123",
      "destination" : "192.168.10.2",
      "no_" : "1",
      "info" : "%s",
      "source" : "10.0.0.6",
      "time" : "0.000000",
      "protocol" : null,
      "length" : "%d"
   }
}
`
	report_expected_summary_and_full := `
 Alert Packet 1:2
---------------------
Event timestamp: 2019-06-18 09:42:22 +0000 UTC
Packet timestamp: 2019-06-18 09:42:22.123321 +0000 UTC
Summary: "%s"
Packet len: %d
Raw packet:
%s`

	json_expected_full := `
{
   "Event_second" : 1560850942,
   "Packet_time" : {
      "Second" : 1560850942,
      "Microsecond" : 123321,
      "Time" : "2019-06-18T09:42:22.123321Z"
   },
   "Packet_length" : %d,
   "Packet_data" : "%s",
   "Sensor_id" : 1,
   "Linktype" : 228,
   "Event_id" : 2,
   "Packet" : {
      "timestamp" : "1560850942123",
      "destination" : "192.168.10.2",
      "no_" : "1",
      "info" : "%s",
      "source" : "10.0.0.6",
      "time" : "0.000000",
      "protocol" : null,
      "length" : "%d",
      "layers" : {}
   }
}
`

	json_gen := func(t *testing.T, obj *Unified2Packet) ([]byte, error) {
		return json.Marshal(obj)
	}

	json_comp_base := func(t *testing.T, expected_bytes, actual_bytes []byte) (expected, actual interface{}) {
		assert.NilError(t, json.Unmarshal(expected_bytes, &expected))
		assert.NilError(t, json.Unmarshal(actual_bytes, &actual))
		return
	}

	json_comp := func(t *testing.T, expected_bytes, actual_bytes []byte) {
		expected, actual := json_comp_base(t, expected_bytes, actual_bytes)
		assert.DeepEqual(t, expected, actual)
	}

	// ignore x[Packet][protocol]
	ignoreProtocol := cmp.FilterPath(func(p cmp.Path) bool {
		return p.GoString() == `root["Packet"].(map[string]interface {})["protocol"]`
	}, cmp.Ignore())

	// ignore any fields deeper than x[Packet][layers]
	ignoreLayers := cmp.FilterPath(func(p cmp.Path) bool {
		return len(p) == 6 && p[:5].GoString() == `root["Packet"].(map[string]interface {})["layers"].(map[string]interface {})`
	}, cmp.Ignore())

	json_comp_ignorepacket_layers := func(t *testing.T, expected_bytes, actual_bytes []byte) {
		expected, actual := json_comp_base(t, expected_bytes, actual_bytes)
		assert.Assert(t, is.DeepEqual(expected, actual, ignoreLayers, ignoreProtocol))
	}

	json_comp_ignorepacket_protocol := func(t *testing.T, expected_bytes, actual_bytes []byte) {
		expected, actual := json_comp_base(t, expected_bytes, actual_bytes)
		assert.Assert(t, is.DeepEqual(expected, actual, ignoreProtocol))
	}

	report_gen := func(t *testing.T, obj *Unified2Packet) ([]byte, error) {
		buff := bytes.Buffer{}
		n, err := obj.WriteTo(&buff)
		assert.Equal(t, n, int64(buff.Len()))
		return buff.Bytes(), err
	}

	report_comp := func(t *testing.T, expected_bytes, actual_bytes []byte) {
		assert.DeepEqual(t, expected_bytes, actual_bytes)
	}

	tests := []test{
		test{
			name:          "plain-json",
			packet_data:   packet,
			packet_uri:    "",
			decode:        false,
			decode_filter: nil,
			hash:          false,
			generator:     json_gen,
			expected:      json_expected_plain,
			arguments:     []interface{}{len(packet), packet_b64},
			comparator:    json_comp,
		},
		test{
			name:          "plain-report",
			packet_data:   packet,
			packet_uri:    "",
			decode:        false,
			decode_filter: nil,
			hash:          false,
			generator:     report_gen,
			expected:      report_expected_plain,
			arguments:     []interface{}{len(packet), packet_hex},
			comparator:    report_comp,
		},
		test{
			name:          "hash-json",
			packet_data:   packet,
			packet_uri:    "",
			decode:        false,
			decode_filter: nil,
			hash:          true,
			generator:     json_gen,
			expected:      json_expected_hash,
			arguments:     []interface{}{len(packet), packet_hash},
			comparator:    json_comp,
		},
		test{
			name:          "hash-report",
			packet_data:   packet,
			packet_uri:    "",
			decode:        false,
			decode_filter: nil,
			hash:          true,
			generator:     report_gen,
			expected:      report_expected_hash,
			arguments:     []interface{}{packet_hash, len(packet)},
			comparator:    report_comp,
		},
		test{
			name:          "summary-json",
			packet_data:   packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: nil,
			hash:          false,
			generator:     json_gen,
			expected:      json_expected_summary,
			arguments:     []interface{}{len(packet), packet_b64, packet_summary, len(packet)},
			comparator:    json_comp_ignorepacket_protocol,
		},
		test{
			name:          "summary-report",
			packet_data:   packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: nil,
			hash:          false,
			generator:     report_gen,
			expected:      report_expected_summary_and_full,
			arguments:     []interface{}{packet_summary, len(packet), packet_hex},
			comparator:    report_comp,
		},
		test{
			name:          "full-json",
			packet_data:   packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: []string{},
			hash:          false,
			generator:     json_gen,
			expected:      json_expected_full,
			arguments:     []interface{}{len(packet), packet_b64, packet_summary, len(packet)},
			comparator:    json_comp_ignorepacket_layers,
		},
		test{
			name:          "full-report",
			packet_data:   packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: []string{},
			hash:          false,
			generator:     report_gen,
			expected:      report_expected_summary_and_full,
			arguments:     []interface{}{packet_summary, len(packet), packet_hex},
			comparator:    report_comp,
		},
		test{
			name:          "summary-pscan-report",
			packet_data:   pscan_packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: nil,
			hash:          false,
			generator:     report_gen,
			expected:      report_expected_summary_and_full,
			arguments:     []interface{}{"Unknown (255)", len(pscan_packet), pscan_packet_hex},
			comparator:    report_comp,
		},
		test{
			name:          "summary-pscan-json",
			packet_data:   pscan_packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: nil,
			hash:          false,
			generator:     json_gen,
			expected:      json_expected_summary,
			arguments:     []interface{}{len(pscan_packet), pscan_packet_b64, "Unknown (255)", len(pscan_packet)},
			comparator:    json_comp_ignorepacket_protocol,
		},
		test{
			name:          "full-pscan-report",
			packet_data:   pscan_packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: []string{"ip", "data"},
			hash:          false,
			generator:     report_gen,
			expected:      report_expected_summary_and_full,
			arguments:     []interface{}{pscan_packet_summary, len(pscan_packet), pscan_packet_hex},
			comparator:    report_comp,
		},
		test{
			name:          "full-pscan-json",
			packet_data:   pscan_packet,
			packet_uri:    "",
			decode:        true,
			decode_filter: []string{"ip", "data"},
			hash:          false,
			generator:     json_gen,
			expected:      json_expected_full,
			arguments:     []interface{}{len(pscan_packet), pscan_packet_b64, strings.Replace(pscan_packet_summary, "\n", "\\n", -1), len(pscan_packet)},
			comparator:    json_comp_ignorepacket_layers,
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestFindVal(t *testing.T) {
	amap := map[string]interface{}{
		"astring": "hello world",
		"amap": map[string]interface{}{
			"anumber": 66,
		},
	}

	assert.Assert(t, is.Nil(findVal(amap, []string{"nothing"})))
	assert.Assert(t, is.Nil(findVal(amap, []string{"astring", "nothing"})))
	assert.Equal(t, findVal(amap, []string{"astring"}), "hello world")
	assert.Equal(t, findVal(amap, []string{"amap", "anumber"}), 66)
}

func TestWriteTo(t *testing.T) {
	evt := &Unified2IDSEvent_legacy{
		Sensor_id:          uint32(1),
		Event_id:           uint32(2),
		Event_time:         aTime,
		Event_info:         aGeneratorEvent,
		Signature_revision: uint32(3),
		Classification:     aClassification,
		Priority_id:        uint32(4),
		Ip_source:          anIPv4_A,
		Ip_destination:     anIPv4_B,
		Sport_itype:        uint16(5),
		Dport_icode:        uint16(6),
		Protocol:           aProtocol,
		Impact_flag:        uint8(32),
		Blocked:            Blocked("Was Dropped"),
	}

	pkt := &Unified2Packet{
		Sensor_id:     1,
		Event_id:      2,
		Event_second:  aTime.Second,
		Packet_time:   aTime,
		Linktype:      228, // DLT_IPV4
		Packet_length: 5,
		Packet_data:   []byte("hello"),
		packet_data:   []byte("hello"),
		Packet_uri:    "",
	}

	report_expected_event := `
 IDS Event 1:2
------------------
Timestamp: 2019-06-18 09:42:22.123321 +0000 UTC
Generator: 2:1, Description: "---"
Classification: 28
Direction: (6) 192.0.2.1:5 -> 192.0.2.255:6
Action: Was Dropped
`
	report_expected_packet := `
 Alert Packet 1:2
---------------------
Event timestamp: 2019-06-18 09:42:22 +0000 UTC
Packet timestamp: 2019-06-18 09:42:22.123321 +0000 UTC
Packet len: 5
Raw packet:
00000000  68 65 6c 6c 6f                                    |hello|
`

	type test struct {
		name     string
		obj      interface{}
		template string
		fallback string
		error    string
		expected string
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			// clear out cached template to ensure its loaded fresh
			if _, ok := templates[test.template]; ok {
				delete(templates, test.template)
			}

			// write object
			buff := bytes.Buffer{}
			n, err := writeTo(test.obj, test.template, test.fallback, &buff)

			// acceptance criteria
			if test.expected != "" {
				assert.NilError(t, err)
				assert.Equal(t, string(buff.Bytes()), test.expected)
			}
			if test.error != "" {
				assert.ErrorContains(t, err, test.error)
				assert.Equal(t, n, int64(0))
			}
			assert.Equal(t, int64(len(buff.Bytes())), n)
		}
	}

	tests := []test{
		test{
			name:     "unknown-template",
			obj:      evt,
			template: "unknown",
			fallback: `{{ "hello" }}`,
			error:    "",
			expected: "hello",
		},
		test{
			name:     "unknown-bad-template",
			obj:      evt,
			template: "unknown",
			fallback: `{{ xxx }}`,
			error:    `function "xxx" not defined`,
			expected: "",
		},
		test{
			name:     "nominal-event",
			obj:      evt,
			template: "event",
			fallback: EventTemplate,
			error:    "",
			expected: report_expected_event,
		},
		test{
			name:     "nominal-packet",
			obj:      pkt,
			template: "packet",
			fallback: PacketTemplate,
			error:    "",
			expected: report_expected_packet,
		},
		test{
			name:     "wrong-template",
			obj:      evt,
			template: "packet",
			fallback: PacketTemplate,
			error:    "can't evaluate field Event_second in type *u2.Unified2IDSEvent_legacy",
			expected: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestDecodePacket(t *testing.T) {
	type test struct {
		name     string
		packet   *Unified2Packet
		decoder  decoder
		summary  bool
		filter   []string
		expected map[string]interface{}
		error    string
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {

			f := func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				assert.Equal(t, packet_second, test.packet.Packet_time.Second)
				assert.Equal(t, packet_microsecond, test.packet.Packet_time.Microsecond)
				assert.Equal(t, linktype, test.packet.Linktype)
				assert.DeepEqual(t, packet_data, test.packet.packet_data)

				assert.Assert(t, is.Contains(options, "-P"))

				if !test.summary {
					assert.Assert(t, is.Contains(options, "-V"))
					if len(test.filter) > 0 {
						assert.Assert(t, is.Contains(options, "-J"))

					}
				}

				for i := 0; i < len(options); i++ {
					switch opt := options[i]; opt {
					case "-P":
					case "-V":
						if test.summary {
							t.Error("Option -V incorrectly passed")
						}

					case "-J":
						if len(test.filter) == 0 {
							t.Error("Option -J incorrectly passed")
						}
						i++
						if i < len(options) {
							filter := options[i]
							assert.Equal(t, filter, strings.Join(test.filter, " "))
						} else {
							t.Error("Expected filter for -J")
						}
					default:
						t.Error("Unexpected option:", opt)

					}

				}

				return test.decoder(
					packet_second,
					packet_microsecond,
					linktype,
					packet_data,
					options,
				)
			}

			err := test.packet.decodePacket(f, test.summary, test.filter)

			assert.DeepEqual(t, test.packet.Packet, test.expected)

			if test.error != "" {
				assert.ErrorContains(t, err, test.error)
			} else {
				assert.NilError(t, err)
			}
		}
	}

	anObject := map[string]interface{}{
		"test1": 111,
	}

	anObjectWithProtocol := func(s string) map[string]interface{} {
		return map[string]interface{}{
			"layers": map[string]interface{}{
				"ip": map[string]interface{}{
					"ip_ip_proto": s,
				},
			},
		}
	}

	anObjectWithData := func(d, i string) map[string]interface{} {
		x := map[string]interface{}{
			"layers": map[string]interface{}{
				"ip": map[string]interface{}{
					"ip_ip_proto": "255",
				},
				"data": map[string]interface{}{
					"data_data_data": d,
				},
			},
		}
		if i != "" {
			x["info"] = i
		}
		return x
	}

	aPacket := func() *Unified2Packet {
		return &Unified2Packet{
			Sensor_id:     1,
			Event_id:      2,
			Event_second:  aTime.Second,
			Packet_time:   aTime,
			Linktype:      228, // DLT_IPV4
			Packet_length: 5,
			Packet_data:   []byte("hello"),
			packet_data:   []byte("hello"),
		}
	}

	tests := []test{
		test{
			name:   "summary-nil",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObject, nil
			},
			summary:  true,
			filter:   nil,
			expected: anObject,
			error:    "",
		},
		test{
			name:   "summary-empty",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObject, nil
			},
			summary:  true,
			filter:   []string{},
			expected: anObject,
			error:    "",
		},
		test{
			name:   "summary-filter",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObject, nil
			},
			summary:  true,
			filter:   []string{"a", "b"},
			expected: anObject,
			error:    "",
		},
		test{
			name:   "full-nil",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObject, nil
			},
			summary:  false,
			filter:   nil,
			expected: anObject,
			error:    "",
		},
		test{
			name:   "full-empty",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObject, nil
			},
			summary:  false,
			filter:   []string{},
			expected: anObject,
			error:    "",
		},
		test{
			name:   "full-empty",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObject, nil
			},
			summary:  false,
			filter:   []string{"a", "b"},
			expected: anObject,
			error:    "",
		},
		test{
			name:   "full-prot-128",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObjectWithProtocol("128"), nil
			},
			summary:  false,
			filter:   nil,
			expected: anObjectWithProtocol("128"),
			error:    "",
		},
		test{
			name:   "full-prot-255",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObjectWithProtocol("255"), nil
			},
			summary:  false,
			filter:   nil,
			expected: anObjectWithProtocol("255"),
			error:    "",
		},
		test{
			name:   "full-data-good",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObjectWithData("68:65:6c:6c:6f", ""), nil
			},
			summary:  false,
			filter:   nil,
			expected: anObjectWithData("68:65:6c:6c:6f", "hello"),
			error:    "",
		},
		test{
			name:   "full-data-bad",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObjectWithData("68:65:6c:6c:6", ""), nil
			},
			summary:  false,
			filter:   nil,
			expected: anObjectWithData("68:65:6c:6c:6", ""),
			error:    "encoding/hex",
		},
		test{
			name:   "anerror",
			packet: aPacket(),
			decoder: func(
				packet_second, packet_microsecond, linktype uint32,
				packet_data []byte,
				options []string,
			) (map[string]interface{}, error) {
				return anObject, anError
			},
			summary:  false,
			filter:   nil,
			expected: nil,
			error:    "An Error",
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}

func TestFuncMap(t *testing.T) {
	type test struct {
		name     string
		template string
		object   interface{}
		expected string
		error    string
	}

	testfunc := func(test *test) func(*testing.T) {
		return func(t *testing.T) {
			err := func() error {
				// initialise template
				tmpl := template.New("test")
				tmpl.Funcs(funcmap)
				_, err := tmpl.Parse(test.template)
				if err != nil {
					return err
				}

				// write template
				buffer := bytes.Buffer{}
				err = tmpl.Execute(&buffer, test.object)

				// aceptance criteria
				assert.Equal(t, string(buffer.Bytes()), test.expected)
				return err
			}()
			if test.error == "" {
				assert.NilError(t, err)
			} else {
				assert.ErrorContains(t, err, test.error)
			}
		}
	}

	tests := []test{
		test{
			name:     "bytes-string",
			template: `{{ . | string }}`,
			object:   []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f},
			expected: "hello",
			error:    "",
		},
		test{
			name:     "string-string",
			template: `{{ . | string }}`,
			object:   "hello",
			expected: "",
			error:    "Can not convert to string",
		},
		test{
			name:     "time-uint32",
			template: `{{ . | time }}`,
			object:   uint32(1560850942),
			expected: "2019-06-18 09:42:22 +0000 UTC",
			error:    "",
		},
		test{
			name:     "time-int",
			template: `{{ . | time }}`,
			object:   1560850942,
			expected: "",
			error:    "wrong type for value; expected uint32; got int",
		},
		test{
			name:     "bytes-hexdump",
			template: `{{ . | hexdump }}`,
			object:   []byte{0x68, 0x65, 0x6c, 0x6c, 0x6f},
			expected: hex.Dump([]byte{0x68, 0x65, 0x6c, 0x6c, 0x6f}),
			error:    "",
		},
		test{
			name:     "unknown",
			template: `{{ . | xxx }}`,
			object:   123,
			expected: "",
			error:    `function "xxx" not defined`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, testfunc(&test))
	}
}
