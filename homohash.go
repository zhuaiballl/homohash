package homohash

import (
	"encoding/binary"
	"errors"
	"hash"
)

const (
	Size      = 32
	BlockSize = 64
	chunk     = 64
)

const (
	init0 = 0
	init1 = 0
	init2 = 0
	init3 = 0
	init4 = 0
	init5 = 0
	init6 = 0
	init7 = 0
)

type homo struct {
	h   [8]uint32
	x   [chunk]byte
	nx  int
	len uint64
}

const (
	magic         = "homo"
	marshaledSize = len(magic) + 8*4 + chunk + 8
)

func (h *homo) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, marshaledSize)
	b = append(b, magic...)
	b = appendUint32(b, h.h[0])
	b = appendUint32(b, h.h[1])
	b = appendUint32(b, h.h[2])
	b = appendUint32(b, h.h[3])
	b = appendUint32(b, h.h[4])
	b = appendUint32(b, h.h[5])
	b = appendUint32(b, h.h[6])
	b = appendUint32(b, h.h[7])
	b = append(b, h.x[:h.nx]...)
	b = b[:len(b)+len(h.x)-int(h.nx)] // already zero
	b = appendUint64(b, h.len)
	return b, nil
}

func (h *homo) UnmarshalBinary(b []byte) error {
	// Check state head
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return errors.New("homohash: invalid hash state identifier")
	}
	if len(b) != marshaledSize {
		return errors.New("homohash: invalid hash state size")
	}
	// Cut off state head
	b = b[len(magic):]
	b, h.h[0] = consumeUint32(b)
	b, h.h[1] = consumeUint32(b)
	b, h.h[2] = consumeUint32(b)
	b, h.h[3] = consumeUint32(b)
	b, h.h[4] = consumeUint32(b)
	b, h.h[5] = consumeUint32(b)
	b, h.h[6] = consumeUint32(b)
	b, h.h[7] = consumeUint32(b)
	b = b[copy(h.x[:], b):]
	b, h.len = consumeUint64(b)
	h.nx = int(h.len % chunk)
	return nil
}

func appendUint64(b []byte, x uint64) []byte {
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], x)
	return append(b, a[:]...)
}

func appendUint32(b []byte, x uint32) []byte {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], x)
	return append(b, a[:]...)
}

func consumeUint64(b []byte) ([]byte, uint64) {
	_ = b[7]
	x := uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
		uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0])<<56
	return b[8:], x
}

func consumeUint32(b []byte) ([]byte, uint32) {
	_ = b[3]
	x := uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0])<<24
	return b[4:], x
}

func (h *homo) Reset() {
	h.h[0] = init0
	h.h[1] = init1
	h.h[2] = init2
	h.h[3] = init3
	h.h[4] = init4
	h.h[5] = init5
	h.h[6] = init6
	h.h[7] = init7
}

func New() hash.Hash {
	h := new(homo)
	return h
}

func (h *homo) Size() int {
	return Size
}

func (h *homo) BlockSize() int {
	return BlockSize
}

func (h *homo) Write(p []byte) (nn int, err error) {
	// TODO: implement Write()
	nn = len(p)
	h.len += uint64(nn)
	if h.nx > 0 {
		n := copy(h.x[h.nx:], p)
		h.nx += n
		if h.nx == chunk {
			block(h, h.x[:])
			h.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= chunk {
		n := len(p) &^ (chunk - 1)
		block(h, p[:n])
		p = p[n:]
	}
	if len(p) > 0 {
		h.nx = copy(h.x[:], p)
	}
	return
}

func (h *homo) Sum(in []byte) []byte {
	// Make a copy of h so that caller can keep writing and summing.
	h0 := *h
	hash := h0.checkSum()
	return append(in, hash[:]...)
}

func (h *homo) checkSum() [Size]byte {
	len := h.len
	// Padding. Add 1 bit and 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		h.Write(tmp[:56-len%64])
	} else {
		h.Write(tmp[:64+56-len%64])
	}

	var digest [Size]byte

	binary.BigEndian.PutUint32(digest[0:], h.h[0])
	binary.BigEndian.PutUint32(digest[4:], h.h[1])
	binary.BigEndian.PutUint32(digest[8:], h.h[2])
	binary.BigEndian.PutUint32(digest[12:], h.h[3])
	binary.BigEndian.PutUint32(digest[16:], h.h[4])
	binary.BigEndian.PutUint32(digest[20:], h.h[5])
	binary.BigEndian.PutUint32(digest[24:], h.h[6])
	binary.BigEndian.PutUint32(digest[28:], h.h[7])

	return digest
}

func block(h *homo, p []byte) {
	// TODO: implement block()
	return
}
