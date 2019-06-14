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

// Package defines types in this file based on Unified2_common.h and
// u2spewfoo program provided in snort distribution 2.9.13.
//
// Support for decoding from binary and encoding to json is provided,
// where appropriate for these structures.
package u2

import (
	"errors"
	"net"
	"time"

	"github.com/kazkansouh/u2text/parser/classification"
	"github.com/kazkansouh/u2text/parser/gen"
	"github.com/kazkansouh/u2text/parser/protocol"
	"github.com/kazkansouh/u2text/parser/sid"
	"github.com/kazkansouh/u2text/parser/u2/encoding"
)

// These values define the tags used in the unified2 records. See
// snort documentation for more information.
const (
	// old, not used in code
	UNIFIED2_EVENT uint32 = 1

	// current

	// see u2spewfoo.c in snort
	UNIFIED2_PACKET uint32 = 2
	// see u2spewfoo.c in snort
	UNIFIED2_IDS_EVENT uint32 = 7
	// see u2spewfoo.c in snort
	UNIFIED2_IDS_EVENT_IPV6 uint32 = 72
	// see u2spewfoo.c in snort
	UNIFIED2_IDS_EVENT_VLAN uint32 = 104
	// see u2spewfoo.c in snort
	UNIFIED2_IDS_EVENT_IPV6_VLAN uint32 = 105
	// see u2spewfoo.c in snort
	UNIFIED2_EXTRA_DATA uint32 = 110

	// see u2spewfoo.c in snort
	UNIFIED2_IDS_EVENT_APPID uint32 = 111
	// see u2spewfoo.c in snort
	UNIFIED2_IDS_EVENT_APPID_IPV6 uint32 = 112
)

// Represents a time within a unified2 record. The time value is
// calculated when the record is read.
type Time struct {
	Second      uint32
	Microsecond uint32
	Time        time.Time `u2:"ignore:*" json:",omitempty"`
}

// Parse a timestamp from the byte stream
func (t *Time) UnmarshalC(data []byte) (uint, error) {
	x := struct {
		Second      uint32
		Microsecond uint32
	}{}

	i, err := encoding.UnmarshalPartial(&x, data)
	if err != nil {
		return 0, err
	}

	t.Second = x.Second
	t.Microsecond = x.Microsecond
	t.Time = time.Unix(int64(t.Second), int64(t.Microsecond)*1000)

	return i, nil
}

//	UNIFIED2_PACKET              uint32 = 2
type Unified2Packet struct {
	Sensor_id     uint32
	Event_id      uint32
	Event_second  uint32
	Packet_time   Time
	Linktype      uint32
	Packet_length uint32

	// Stores a byte array of the captured packet. This can be
	// cleared by the caller (e.g. when marshalling) as an
	// internal reference is kept.
	Packet_data []byte `u2:"slice-length:*" json:",omitempty"`

	// call CalculateHash to populate
	Packet_hash string `u2:"ignore:*" json:",omitempty"`

	// Call DecodePacket to populate
	Packet map[string]interface{} `u2:"ignore:*" json:",omitempty"`

	// Copy of Packet_data, used by DisplayHash/DecodePacket
	packet_data []byte `u2:"ignore:*" json:"-"`
}

// Restore Packet_data from internal copy, useful if Packet_data has
// been cleared for marshalling.
func (x *Unified2Packet) RestorePacketData() {
	x.Packet_data = x.packet_data
}

// Combine both Generator and Signature id maps into single type for
// convenience.
type MessageMap struct {
	G gen.GenMap
	S sid.SidMap
	P protocol.ProtocolMap
	C classification.ClassMap
}

// Bonds a type to a Signature and Generator ID to message map
type MessageBonder interface {
	BondMessageMap(m *MessageMap)
}

// Represents the event id (consisting of a generator id and signature
// (or alert) id).  When unmarshalling only the uint32s are
// used. However the maps are used when marshalling to map the ids
// onto text descriptions.
type EventID struct {
	Signature_id uint32
	Generator_id uint32
	mmap         *MessageMap `u2:"ignore:*"`
}

func (s *EventID) BondMessageMap(m *MessageMap) {
	s.mmap = m
}

// Represents the protocol field of an event. mmap is used to convert
// the protocol number into text.
type Protocol struct {
	Number uint8
	mmap   *MessageMap `u2:"ignore:*"`
}

func (s *Protocol) BondMessageMap(m *MessageMap) {
	s.mmap = m
}

// Represents the classification id.  When unmarshalling only the
// uint32 is used. However the maps are used when marshalling to map
// the ids onto text descriptions.
type Classification struct {
	Id   uint32
	mmap *MessageMap `u2:"ignore:*"`
}

func (s *Classification) BondMessageMap(m *MessageMap) {
	s.mmap = m
}

type IPv4 net.IP

// Consume 4 bytes from data for ipv4
func (ip *IPv4) UnmarshalC(data []byte) (uint, error) {
	if len(data) < 4 {
		return 0, errors.New("Stream too short to parse IPv4")
	}
	*ip = data[:4]

	return 4, nil
}

// Represents the blocked field in an event. Should take a value from
// the following: "Was NOT Dropped", "Was Dropped", "Would Have
// Dropped". See snort documentation for more information.
type Blocked string

// Consume 1 bytes and save as string
func (blk *Blocked) UnmarshalC(data []byte) (uint, error) {
	if len(data) < 1 {
		return 0, errors.New("Stream too short to blocked (uint8)")
	}

	switch data[0] {
	case 0:
		*blk = "Was NOT Dropped"
	case 1:
		*blk = "Was Dropped"
	case 2:
		*blk = "Would Have Dropped"
	default:
		return 0, errors.New("Out of range value for blocked field")
	}

	return 1, nil
}

// 	UNIFIED2_IDS_EVENT           uint32 = 7
type Unified2IDSEvent_legacy struct {
	Sensor_id          uint32
	Event_id           uint32
	Event_time         Time
	Event_info         EventID
	Signature_revision uint32
	Classification     Classification
	Priority_id        uint32
	Ip_source          IPv4
	Ip_destination     IPv4
	Sport_itype        uint16
	Dport_icode        uint16
	Protocol           Protocol
	Impact_flag        uint8 //sets packet_action
	Impact             uint8
	Blocked            Blocked
}

func (x *Unified2IDSEvent_legacy) BondMessageMap(m *MessageMap) {
	x.Event_info.BondMessageMap(m)
	x.Protocol.BondMessageMap(m)
	x.Classification.BondMessageMap(m)
}

type IPv6 net.IP

// Consume 16 bytes from data for ipv6
func (ip *IPv6) UnmarshalC(data []byte) (uint, error) {
	if len(data) < 16 {
		return 0, errors.New("Stream too short to parse IPv6")
	}
	*ip = data[:16]

	return 16, nil
}

//	UNIFIED2_IDS_EVENT_IPV6      uint32 = 72
type Unified2IDSEventIPv6_legacy struct {
	Sensor_id          uint32
	Event_id           uint32
	Event_time         Time
	Event_info         EventID
	Signature_revision uint32
	Classification     Classification
	Priority_id        uint32
	Ip_source          IPv6
	Ip_destination     IPv6
	Sport_itype        uint16
	Dport_icode        uint16
	Protocol           Protocol
	Impact_flag        uint8
	Impact             uint8
	Blocked            uint8
}

func (x *Unified2IDSEventIPv6_legacy) BondMessageMap(m *MessageMap) {
	x.Event_info.BondMessageMap(m)
	x.Protocol.BondMessageMap(m)
	x.Classification.BondMessageMap(m)
}

//	UNIFIED2_IDS_EVENT_VLAN      uint32 = 104
type Unified2IDSEvent struct {
	Sensor_id          uint32
	Event_id           uint32
	Event_time         Time
	Event_info         EventID
	Signature_revision uint32
	Classification     Classification
	Priority_id        uint32
	Ip_source          IPv4
	Ip_destination     IPv4
	Sport_itype        uint16
	Dport_icode        uint16
	Protocol           Protocol
	Impact_flag        uint8 //overloads packet_action
	Impact             uint8
	Blocked            Blocked
	Mpls_label         uint32
	VlanId             uint16
	Pad2               uint16 //Policy ID
}

func (x *Unified2IDSEvent) BondMessageMap(m *MessageMap) {
	x.Event_info.BondMessageMap(m)
	x.Protocol.BondMessageMap(m)
	x.Classification.BondMessageMap(m)
}

//	UNIFIED2_IDS_EVENT_IPV6_VLAN uint32 = 105
type Unified2IDSEventIPv6 struct {
	Sensor_id          uint32
	Event_id           uint32
	Event_time         Time
	Event_info         EventID
	Signature_revision uint32
	Classification     Classification
	Priority_id        uint32
	Ip_source          IPv6
	Ip_destination     IPv6
	Sport_itype        uint16
	Dport_icode        uint16
	Protocol           Protocol
	Impact_flag        uint8
	Impact             uint8
	Blocked            Blocked
	Mpls_label         uint32
	VlanId             uint16
	Pad2               uint16 /*could be IPS Policy local id to support local sensor alerts*/
}

func (x *Unified2IDSEventIPv6) BondMessageMap(m *MessageMap) {
	x.Event_info.BondMessageMap(m)
	x.Protocol.BondMessageMap(m)
	x.Classification.BondMessageMap(m)
}

//	UNIFIED2_IDS_EVENT_APPID      uint32 = 111
type Unified2IDSEvent_appid struct {
	Sensor_id          uint32
	Event_id           uint32
	Event_time         Time
	Event_info         EventID
	Signature_revision uint32
	Classification     Classification
	Priority_id        uint32
	Ip_source          IPv4
	Ip_destination     IPv4
	Sport_itype        uint16
	Dport_icode        uint16
	Protocol           Protocol
	Impact_flag        uint8 //overloads packet_action
	Impact             uint8
	Blocked            Blocked
	Mpls_label         uint32
	VlanId             uint16
	Pad2               uint16 //Policy ID
	App_name           string `u2:"string-length:64"`
}

func (x *Unified2IDSEvent_appid) BondMessageMap(m *MessageMap) {
	x.Event_info.BondMessageMap(m)
	x.Protocol.BondMessageMap(m)
	x.Classification.BondMessageMap(m)
}

//	UNIFIED2_IDS_EVENT_APPID_IPV6 uint32 = 112
type Unified2IDSEventIPv6_appid struct {
	Sensor_id          uint32
	Event_id           uint32
	Event_time         Time
	Event_info         EventID
	Signature_revision uint32
	Classification     Classification
	Priority_id        uint32
	Ip_source          IPv6
	Ip_destination     IPv6
	Sport_itype        uint16
	Dport_icode        uint16
	Protocol           Protocol
	Impact_flag        uint8
	Impact             uint8
	Blocked            Blocked
	Mpls_label         uint32
	VlanId             uint16
	Pad2               uint16 /*could be IPS Policy local id to support local sensor alerts*/
	App_name           string `u2:"string-length:64"`
}

func (x *Unified2IDSEventIPv6_appid) BondMessageMap(m *MessageMap) {
	x.Event_info.BondMessageMap(m)
	x.Protocol.BondMessageMap(m)
	x.Classification.BondMessageMap(m)
}
