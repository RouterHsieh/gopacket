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

type v2header unix.Tpacket2Hdr

func (v2 *v2header) getStatus() int {
	return int(atomic.LoadUint32(&v2.Status))
}

func (v2 *v2header) clearStatus() {
	atomic.StoreUint32(&v2.Status, 0)
}

func (v2 *v2header) getTime() time.Time {
	return time.Unix(int64(v2.Sec), int64(v2.Nsec))
}

func (v2 *v2header) getData(opt *options) []byte {
	data := makeSlice(uintptr(unsafe.Pointer(v2))+uintptr(v2.Mac), int(v2.Snaplen))
	return insertVlanHeader(data, int(v2.Vlan_tci), opt)
}

func (v2 *v2header) getLength() int {
	return int(v2.Len)
}

func (v2 *v2header) getIfaceIndex() int {
	sll := (*unix.RawSockaddrLinklayer)(unsafe.Pointer(uintptr(unsafe.Pointer(v2)) + uintptr(tpAlign(int(unix.SizeofTpacket2Hdr)))))
	return int(sll.Ifindex)
}

func (v2 *v2header) next() bool {
	return false
}

func (v2 *v2header) getVLAN() int {
	return -1
}
