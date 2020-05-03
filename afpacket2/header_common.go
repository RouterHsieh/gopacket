// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

package afpacket2

import (
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type header interface {
	// getStatus returns the TPacket status of the current header.
	getStatus() int
	// clearStatus clears the status of the current header, releasing its
	// underlying data back to the kernel for future use with new packets.
	// Using the header after calling clearStatus is an error.  clearStatus
	// should only be called after next() returns false.
	clearStatus()
	// getTime returns the timestamp for the current packet pointed to by
	// the header.
	getTime() time.Time
	// getData returns the packet data pointed to by the current header.
	getData(opts *options) []byte
	// getLength returns the total length of the packet.
	getLength() int
	// getIfaceIndex returns the index of the network interface
	// where the packet was seen. The index can later be translated to a name.
	getIfaceIndex() int
	// getVLAN returns the VLAN of a packet if it was provided out-of-band
	getVLAN() int
	// next moves this header to point to the next packet it contains,
	// returning true on success (in which case getTime and getData will
	// return values for the new packet) or false if there are no more
	// packets (in which case clearStatus should be called).
	next() bool
}

const (
	VLAN_HLEN        = 4 // vlan header length, 32 bits
	ETH_ALEN         = 6 // ethernet address length, 48 bits
	tpacketAlignment = uint(unix.TPACKET_ALIGNMENT)
)

func tpAlign(x int) int {
	return int((uint(x) + tpacketAlignment - 1) &^ (tpacketAlignment - 1))
}

func makeSlice(start uintptr, length int) (data []byte) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length
	return
}

func insertVlanHeader(data []byte, vlanTCI int, opts *options) []byte {
	if vlanTCI == 0 || !opts.addVLANHeader {
		return data
	}
	eth := make([]byte, 0, len(data)+VLAN_HLEN)
	eth = append(eth, data[0:ETH_ALEN*2]...)
	eth = append(eth, []byte{0x81, 0, byte((vlanTCI >> 8) & 0xff), byte(vlanTCI & 0xff)}...)
	return append(eth, data[ETH_ALEN*2:]...)
}
