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

// Simple http server that adds files to a cache (received over a
// channel) and serves them via http
package packetserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/kazkansouh/u2text/parser/packet"
	"github.com/kazkansouh/u2text/parser/u2"
)

// Stores state information for packet server
type PacketServer struct {
	// New packets that are to be made available should be sent
	// over this channel. Requires that a packet hash has already
	// been calculated before it is passed in.
	//
	// When server is finished with, close the channel to shut it
	// down
	Packets chan *u2.Unified2Packet

	// Any errors raised by server are sent here. Channel is
	// closed when server exits.
	Errors chan error

	// Config for server
	server http.Server

	// Cache directory
	cacheDir string
}

// Setup a new packet server that binds to 'address' and serves files
// from 'directory'.
func NewPacketServer(address, directory string) *PacketServer {
	pkt := PacketServer{}
	pkt.server.Addr = address
	pkt.server.Handler = http.FileServer(http.Dir(directory))

	pkt.cacheDir = directory

	pkt.Packets = make(chan *u2.Unified2Packet, 0)
	pkt.Errors = make(chan error, 1)

	return &pkt
}

func (svr *PacketServer) mainloop() {
	done := make(chan struct{}, 0)
	defer func() {
		// first, shutdown server
		if err := svr.server.Shutdown(context.Background()); err != nil {
			svr.Errors <- err
		}
		close(done)
	}()

	// Start server
	go func() {
		// blocks until svr.Shutdown as been executed
		if err := svr.server.ListenAndServe(); err != http.ErrServerClosed {
			svr.Errors <- err
		}

		// wait for defer (above) to finish
		<-done

		// notify calling process the server is finished
		close(svr.Errors)

		// bleed out packets in channel to prevent deadlock,
		// calling process should close channel when its done
		for {
			_, ok := <-svr.Packets
			if !ok {
				break
			}
		}
	}()

	// ensure cache is a directory before writing files to it
	if dirinfo, err := os.Stat(svr.cacheDir); err != nil {
		svr.Errors <- err
		return
	} else {
		if !dirinfo.IsDir() {
			svr.Errors <- fmt.Errorf("%s is not a directory", svr.cacheDir)
			return
		}
	}

	for {
		pkt, ok := <-svr.Packets
		if !ok {
			break
		}
		if !strings.HasPrefix(pkt.Packet_hash, "sha256:") {
			svr.Errors <- errors.New("Received packet without hash")
			break
		}

		// open file
		file, err := os.OpenFile(
			filepath.Join(
				svr.cacheDir,
				pkt.Packet_hash[7:]+".pcap"),
			os.O_WRONLY|os.O_CREATE|os.O_EXCL,
			0640)
		if os.IsExist(err) {
			// file with same hash exists, skip
			continue
		}
		if err != nil {
			svr.Errors <- err
			break
		}

		// write file
		packet_data := pkt.OriginalPacketData()
		pcaphdr := packet.NewPcap(
			pkt.Packet_time.Second,
			pkt.Packet_time.Microsecond,
			pkt.Linktype,
			uint32(len(packet_data)))

		if err := binary.Write(file, binary.LittleEndian, pcaphdr); err != nil {
			svr.Errors <- err
			file.Close()
			break
		}

		if err := binary.Write(file, binary.LittleEndian, packet_data); err != nil {
			svr.Errors <- err
			file.Close()
			break
		}
		file.Close()
	}
}

// Starts http server running, stop by closing Packets channel. When
// server stops, the Errors channel is closed. If server stops due to
// an error, an error will first be sent on the Errors channel.
func (svr *PacketServer) Start() {
	go svr.mainloop()
}
