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

// v1header implemented header interface
type v1header struct {
	tpHeader *unix.TpacketHdr
	sll      *unix.RawSockaddrLinklayer
	data     []byte
}

func newV1Header(rawPtr unsafe.Pointer) *v1header {
	h := (*unix.TpacketHdr)(rawPtr)
	v1 := &v1header{
		tpHeader: h,
		sll:      (*unix.RawSockaddrLinklayer)(unsafe.Pointer(uintptr(rawPtr) + uintptr(tpAlign(int(unix.SizeofTpacketHdr))))),
		data:     makeSlice(uintptr(rawPtr)+uintptr(h.Mac), int(h.Snaplen)),
	}
	return v1
}

func (v1 *v1header) getStatus() int {
	// Status is used by kernel concurrently, so we need to use atomic to access it
	return int(atomic.LoadUint64(&v1.tpHeader.Status))
}

func (v1 *v1header) clearStatus() {
	// Status is used by kernel concurrently, so we need to use atomic to access it
	atomic.StoreUint64(&v1.tpHeader.Status, 0)
}

func (v1 *v1header) getTime() time.Time {
	return time.Unix(int64(v1.tpHeader.Sec), int64(v1.tpHeader.Usec)*1000)
}

func (v1 *v1header) getData(opts *options) []byte {
	return v1.data
}

func (v1 *v1header) getLength() int {
	return int(v1.tpHeader.Len)
}

func (v1 *v1header) getIfaceIndex() int {
	return int(v1.sll.Ifindex)
}

func (v1 *v1header) next() bool {
	return false
}

func (v1 *v1header) getVLAN() int {
	return -1
}
