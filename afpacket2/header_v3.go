// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

package afpacket2

import (
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type v3wrapper struct {
	block    *unix.TpacketBlockDesc
	blockhdr *unix.TpacketHdrV1
	packet   *unix.Tpacket3Hdr
	used     uint32
}

func newV3Wrapper(rawPtr unsafe.Pointer) v3wrapper {
	b := (*unix.TpacketBlockDesc)(rawPtr)
	hdr := (*unix.TpacketHdrV1)(unsafe.Pointer(&b.Hdr[0]))
	v3 := v3wrapper{
		block:    b,
		blockhdr: hdr,
		packet:   (*unix.Tpacket3Hdr)(unsafe.Pointer(uintptr(rawPtr) + uintptr(hdr.Offset_to_first_pkt))),
	}
	return v3
}

func (v3 *v3wrapper) getStatus() int {
	return int(atomic.LoadUint32(&v3.packet.Status))
}

func (v3 *v3wrapper) clearStatus() {
	atomic.StoreUint32(&v3.packet.Status, 0)
}

func (v3 *v3wrapper) getTime() time.Time {
	return time.Unix(int64(v3.packet.Sec), int64(v3.packet.Nsec))
}

func (v3 *v3wrapper) getData(opts *options) []byte {
	data := makeSlice(uintptr(unsafe.Pointer(v3.packet))+uintptr(v3.packet.Mac), int(v3.packet.Snaplen))
	return insertVlanHeader(data, int(v3.packet.Hv1.Vlan_tci), opts)
}

func (v3 *v3wrapper) getLength() int {
	return int(v3.packet.Len)
}

func (v3 *v3wrapper) getIfaceIndex() int {
	sll := (*unix.RawSockaddrLinklayer)(unsafe.Pointer(uintptr(unsafe.Pointer(v3.packet)) + uintptr(tpAlign(int(unix.SizeofTpacket3Hdr)))))
	return int(sll.Ifindex)
}

func (v3 *v3wrapper) next() bool {
	v3.used += 1
	if v3.used >= v3.blockhdr.Num_pkts {
		return false
	}
	offset := uintptr(0)
	if v3.packet.Next_offset != 0 {
		offset += uintptr(v3.packet.Next_offset)
	} else {
		offset += uintptr(tpAlign(int(v3.packet.Snaplen) + int(v3.packet.Mac)))
	}
	v3.packet = (*unix.Tpacket3Hdr)(unsafe.Pointer(uintptr(unsafe.Pointer(v3.packet)) + offset))
	return true
}

func (v3 *v3wrapper) getVLAN() int {
	if unix.TP_STATUS_VLAN_VALID&atomic.LoadUint32(&v3.packet.Status) != 0 {
		return int(0xffff & v3.packet.Hv1.Vlan_tci)
	}
	return -1
}
