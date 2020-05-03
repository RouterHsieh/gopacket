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

type v2header struct {
	tpHeader *unix.Tpacket2Hdr
	sll      *unix.RawSockaddrLinklayer
	data     []byte
}

func newV2Header(rawPtr unsafe.Pointer) *v2header {
	h := (*unix.Tpacket2Hdr)(rawPtr)
	v2 := &v2header{
		tpHeader: h,
		sll:      (*unix.RawSockaddrLinklayer)(unsafe.Pointer(uintptr(rawPtr) + uintptr(tpAlign(int(unix.SizeofTpacket2Hdr))))),
		data:     makeSlice(uintptr(rawPtr)+uintptr(h.Mac), int(h.Snaplen)),
	}
	return v2
}

func (v2 *v2header) getStatus() int {
	return int(atomic.LoadUint32(&v2.tpHeader.Status))
}

func (v2 *v2header) clearStatus() {
	atomic.StoreUint32(&v2.tpHeader.Status, 0)
}

func (v2 *v2header) getTime() time.Time {
	return time.Unix(int64(v2.tpHeader.Sec), int64(v2.tpHeader.Nsec))
}

func (v2 *v2header) getData(opt *options) []byte {
	return insertVlanHeader(v2.data, int(v2.tpHeader.Vlan_tci), opt)
}

func (v2 *v2header) getLength() int {
	return int(v2.tpHeader.Len)
}

func (v2 *v2header) getIfaceIndex() int {
	return int(v2.sll.Ifindex)
}

func (v2 *v2header) next() bool {
	return false
}

func (v2 *v2header) getVLAN() int {
	return -1
}
