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

type v1header unix.TpacketHdr

func (v1 *v1header) getStatus() int {
	// Status is used by kernel concurrently, so we need to use atomic to access it
	return int(atomic.LoadUint64(&v1.Status))
}

func (v1 *v1header) clearStatus() {
	// Status is used by kernel concurrently, so we need to use atomic to access it
	atomic.StoreUint64(&v1.Status, 0)
}

func (v1 *v1header) getTime() time.Time {
	return time.Unix(int64(v1.Sec), int64(v1.Usec)*1000)
}

func (v1 *v1header) getData(opts *options) []byte {
	return makeSlice(uintptr(unsafe.Pointer(v1))+uintptr(v1.Mac), int(v1.Snaplen))
}

func (v1 *v1header) getLength() int {
	return int(v1.Len)
}

func (v1 *v1header) getIfaceIndex() int {
	sll := (*unix.RawSockaddrLinklayer)(unsafe.Pointer(uintptr(unsafe.Pointer(v1)) + uintptr(tpAlign(int(unix.SizeofTpacketHdr)))))
	return int(sll.Ifindex)
}

func (v1 *v1header) next() bool {
	return false
}

func (v1 *v1header) getVLAN() int {
	return -1
}
