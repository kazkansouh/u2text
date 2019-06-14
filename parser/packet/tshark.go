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

// Translates a raw frame into a json structure by calling
// TShark. Requires packet is wrapped into a pcap file and piped to
// TShark with appropriate command line arguments. TShark will output
// to stdout a json representation of the packet.
package packet

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os/exec"
)

// Represents a pcap file with a single packet, i.e. combines the
// global and packet headers into a single structure. Note,
// packet_data is not included as its encoding/binary does not support
// slice in struct.  Amalgamated structure based on definitions at:
// https://wiki.wireshark.org/Development/LibpcapFileFormat
type SingletonPcap struct {
	// magic_number: used to detect the file format itself and the
	// byte ordering. The writing application writes 0xa1b2c3d4
	// with it's native byte ordering format into this field. The
	// reading application will read either 0xa1b2c3d4 (identical)
	// or 0xd4c3b2a1 (swapped). If the reading application reads
	// the swapped 0xd4c3b2a1 value, it knows that all the
	// following fields will have to be swapped too. For
	// nanosecond-resolution files, the writing application writes
	// 0xa1b23c4d, with the two nibbles of the two lower-order
	// bytes swapped, and the reading application will read either
	// 0xa1b23c4d (identical) or 0x4d3cb2a1 (swapped).
	Magic_number uint32

	// version_major: the version number of this file format
	// (current version_major is 2)
	Version_major uint16

	// version_minor: the version number of this file format
	// (current version_minor is 4)
	Version_minor uint16

	// thiszone: the correction time in seconds between GMT (UTC)
	// and the local timezone of the following packet header
	// timestamps. Examples: If the timestamps are in GMT (UTC),
	// thiszone is simply 0. If the timestamps are in Central
	// European time (Amsterdam, Berlin, ...) which is GMT + 1:00,
	// thiszone must be -3600. In practice, time stamps are always
	// in GMT, so thiszone is always 0.
	Thiszone int32

	// sigfigs: in theory, the accuracy of time stamps in the
	// capture; in practice, all tools set it to 0
	Sigfigs uint32

	// snaplen: the "snapshot length" for the capture (typically
	// 65535 or even more, but might be limited by the user), see:
	// incl_len vs. orig_len below
	Snaplen uint32

	// network: link-layer header type, specifying the type of
	// headers at the beginning of the packet (e.g. 1 for
	// Ethernet, see tcpdump.org's link-layer header types page
	// for details); this can be various types such as 802.11,
	// 802.11 with various radio information, PPP, Token Ring,
	// FDDI, etc.
	Network uint32

	// ts_sec: the date and time when this packet was
	// captured. This value is in seconds since January 1, 1970
	// 00:00:00 GMT; this is also known as a UN*X time_t. You can
	// use the ANSI C time() function from time.h to get this
	// value, but you might use a more optimized way to get this
	// timestamp value. If this timestamp isn't based on GMT
	// (UTC), use thiszone from the global header for adjustments.
	Ts_sec uint32

	// ts_usec: in regular pcap files, the microseconds when this
	// packet was captured, as an offset to ts_sec. In
	// nanosecond-resolution files, this is, instead, the
	// nanoseconds when the packet was captured, as an offset to
	// ts_sec. Beware: this value shouldn't reach 1 second (in
	// regular pcap files 1 000 000; in nanosecond-resolution
	// files, 1 000 000 000); in this case ts_sec must be
	// increased instead!
	Ts_usec uint32

	// incl_len: the number of bytes of packet data actually
	// captured and saved in the file. This value should never
	// become larger than orig_len or the snaplen value of the
	// global header.
	Incl_len uint32

	// orig_len: the length of the packet as it appeared on the
	// network when it was captured. If incl_len and orig_len
	// differ, the actually saved packet size was limited by
	// snaplen.
	Orig_len uint32
}

// Assemble a singleton pcap structure with standard values assigned
func NewPcap(packet_second, packet_microsecond, linktype, packet_len uint32) *SingletonPcap {

	return &SingletonPcap{
		Magic_number:  0xa1b2c3d4,
		Version_major: 2,
		Version_minor: 4,
		Thiszone:      0,
		Sigfigs:       0,
		Snaplen:       65535,
		Network:       linktype,
		Ts_sec:        packet_second,
		Ts_usec:       packet_microsecond,
		Incl_len:      packet_len,
		Orig_len:      packet_len,
	}
}

// Run TShark on the given packet to obtain a json object.
//
// link_type: should be a standard pcap type that corresponds to the
// packet_data encapsulation (see
// https://www.tcpdump.org/linktypes.html). e.g. for standard layer
// 2/ethernet captures it should be set to 1 or for layer 3/ipv4
// captures it could be 228.
//
// packet_second, packet_microsecond: only used for documentation
// purposes in generated json.
//
// packet_data: raw bytes of the packet in format determined by
// link_type.
func ParsePacket(packet_second, packet_microsecond, linktype uint32, packet_data []byte, options []string) (map[string]interface{}, error) {
	pcap := NewPcap(packet_second, packet_microsecond, linktype, uint32(len(packet_data)))

	// -x hex dumps, -V full parse, -P summary information
	cmd := exec.Command("tshark", append([]string{"-r", "-", "-T", "ek"}, options...)...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	defer func() {
		// the return code does not matter, just asynchronously
		// free resources
		go func() {
			cmd.Wait()
		}()
	}()
	if err := binary.Write(stdin, binary.LittleEndian, pcap); err != nil {
		return nil, err
	}
	if err := binary.Write(stdin, binary.LittleEndian, packet_data); err != nil {
		return nil, err
	}
	if err := stdin.Close(); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(stdout)
	// first json object only contains meta data
	var index interface{}
	if err := dec.Decode(&index); err != nil {
		return nil, err
	}

	var pkt interface{}
	if err := dec.Decode(&pkt); err != nil {
		return nil, err
	}

	if pkt, ok := pkt.(map[string]interface{}); ok {
		return pkt, nil
	}

	return nil, errors.New("Unexpected json object received from tshark")
}
