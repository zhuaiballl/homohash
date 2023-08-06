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

const (
	ind0  = 40
	ind1  = 37
	ind2  = 56
	ind3  = 15
	ind4  = 50
	ind5  = 32
	ind6  = 61
	ind7  = 62
	ind8  = 8
	ind9  = 43
	ind10 = 20
	ind11 = 7
	ind12 = 25
	ind13 = 51
	ind14 = 1
	ind15 = 26
	ind16 = 38
	ind17 = 21
	ind18 = 13
	ind19 = 45
	ind20 = 57
	ind21 = 23
	ind22 = 6
	ind23 = 16
	ind24 = 17
	ind25 = 31
	ind26 = 35
	ind27 = 42
	ind28 = 55
	ind29 = 9
	ind30 = 59
	ind31 = 36
	ind32 = 2
	ind33 = 19
	ind34 = 58
	ind35 = 29
	ind36 = 44
	ind37 = 63
	ind38 = 0
	ind39 = 48
	ind40 = 33
	ind41 = 11
	ind42 = 34
	ind43 = 4
	ind44 = 54
	ind45 = 46
	ind46 = 39
	ind47 = 52
	ind48 = 18
	ind49 = 47
	ind50 = 10
	ind51 = 41
	ind52 = 53
	ind53 = 28
	ind54 = 49
	ind55 = 5
	ind56 = 30
	ind57 = 12
	ind58 = 60
	ind59 = 14
	ind60 = 27
	ind61 = 22
	ind62 = 24
	ind63 = 3
)

const (
	p0  = 96
	p1  = 213
	p2  = 79
	p3  = 9
	p4  = 42
	p5  = 123
	p6  = 77
	p7  = 11
	p8  = 93
	p9  = 116
	p10 = 105
	p11 = 29
	p12 = 79
	p13 = 67
	p14 = 24
	p15 = 71
	p16 = 49
	p17 = 153
	p18 = 106
	p19 = 45
	p20 = 133
	p21 = 180
	p22 = 111
	p23 = 231
	p24 = 92
	p25 = 27
	p26 = 95
	p27 = 222
	p28 = 40
	p29 = 85
	p30 = 13
	p31 = 125
	p32 = 165
	p33 = 176
	p34 = 41
	p35 = 206
	p36 = 7
	p37 = 96
	p38 = 171
	p39 = 113
	p40 = 26
	p41 = 134
	p42 = 61
	p43 = 213
	p44 = 143
	p45 = 127
	p46 = 47
	p47 = 180
	p48 = 14
	p49 = 152
	p50 = 149
	p51 = 204
	p52 = 17
	p53 = 177
	p54 = 116
	p55 = 195
	p56 = 77
	p57 = 248
	p58 = 255
	p59 = 72
	p60 = 127
	p61 = 213
	p62 = 55
	p63 = 129
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
	if h.len == 0 {
		h.h[0] = uint32(galMultiply(p[0], p0)) | uint32(galMultiply(p[0], p1))<<8 | uint32(galMultiply(p[0], p2))<<16 | uint32(galMultiply(p[0], p3))<<24
		h.h[1] = uint32(galMultiply(p[0], p4)) | uint32(galMultiply(p[0], p5))<<8 | uint32(galMultiply(p[0], p6))<<16 | uint32(galMultiply(p[0], p7))<<24
		h.h[2] = uint32(galMultiply(p[0], p8)) | uint32(galMultiply(p[0], p9))<<8 | uint32(galMultiply(p[0], p10))<<16 | uint32(galMultiply(p[0], p11))<<24
		h.h[3] = uint32(galMultiply(p[0], p12)) | uint32(galMultiply(p[0], p13))<<8 | uint32(galMultiply(p[0], p14))<<16 | uint32(galMultiply(p[0], p15))<<24
		h.h[4] = uint32(galMultiply(p[0], p16)) | uint32(galMultiply(p[0], p17))<<8 | uint32(galMultiply(p[0], p18))<<16 | uint32(galMultiply(p[0], p19))<<24
		h.h[5] = uint32(galMultiply(p[0], p20)) | uint32(galMultiply(p[0], p21))<<8 | uint32(galMultiply(p[0], p22))<<16 | uint32(galMultiply(p[0], p23))<<24
		h.h[6] = uint32(galMultiply(p[0], p24)) | uint32(galMultiply(p[0], p25))<<8 | uint32(galMultiply(p[0], p26))<<16 | uint32(galMultiply(p[0], p27))<<24
		h.h[7] = uint32(galMultiply(p[0], p28)) | uint32(galMultiply(p[0], p29))<<8 | uint32(galMultiply(p[0], p30))<<16 | uint32(galMultiply(p[0], p31))<<24
	}
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
	// Padding. Add 0 bits until 56 bytes mod 64.
	var tmp [64]byte
	//if len%64 < 56 {
	//	h.Write(tmp[:56-len%64])
	//} else {
	//	h.Write(tmp[:64+56-len%64])
	//}
	if len%64 != 0 {
		h.Write(tmp[:64-len%64])
	}

	var hest [Size]byte

	binary.BigEndian.PutUint32(hest[0:], h.h[0])
	binary.BigEndian.PutUint32(hest[4:], h.h[1])
	binary.BigEndian.PutUint32(hest[8:], h.h[2])
	binary.BigEndian.PutUint32(hest[12:], h.h[3])
	binary.BigEndian.PutUint32(hest[16:], h.h[4])
	binary.BigEndian.PutUint32(hest[20:], h.h[5])
	binary.BigEndian.PutUint32(hest[24:], h.h[6])
	binary.BigEndian.PutUint32(hest[28:], h.h[7])

	return hest
}

// block updates h[] in h based on content of p[], which is a block of data
func block(h *homo, p []byte) {
	h0, h1, h2, h3, h4, h5, h6, h7 := h.h[0], h.h[1], h.h[2], h.h[3], h.h[4], h.h[5], h.h[6], h.h[7]
	for len(p) >= chunk {
		h0 = uint32(galMultiply(p[ind0], p0)) | uint32(galMultiply(p[ind1], p1))<<8 | uint32(galMultiply(p[ind2], p2))<<16 | uint32(galMultiply(p[ind3], p3))<<24
		h1 = uint32(galMultiply(p[ind4], p4)) | uint32(galMultiply(p[ind5], p5))<<8 | uint32(galMultiply(p[ind6], p6))<<16 | uint32(galMultiply(p[ind7], p7))<<24
		h2 = uint32(galMultiply(p[ind8], p8)) | uint32(galMultiply(p[ind9], p9))<<8 | uint32(galMultiply(p[ind10], p10))<<16 | uint32(galMultiply(p[ind11], p11))<<24
		h3 = uint32(galMultiply(p[ind12], p12)) | uint32(galMultiply(p[ind13], p13))<<8 | uint32(galMultiply(p[ind14], p14))<<16 | uint32(galMultiply(p[ind15], p15))<<24
		h4 = uint32(galMultiply(p[ind16], p16)) | uint32(galMultiply(p[ind17], p17))<<8 | uint32(galMultiply(p[ind18], p18))<<16 | uint32(galMultiply(p[ind19], p19))<<24
		h5 = uint32(galMultiply(p[ind20], p20)) | uint32(galMultiply(p[ind21], p21))<<8 | uint32(galMultiply(p[ind22], p22))<<16 | uint32(galMultiply(p[ind23], p23))<<24
		h6 = uint32(galMultiply(p[ind24], p24)) | uint32(galMultiply(p[ind25], p25))<<8 | uint32(galMultiply(p[ind26], p26))<<16 | uint32(galMultiply(p[ind27], p27))<<24
		h7 = uint32(galMultiply(p[ind28], p28)) | uint32(galMultiply(p[ind29], p29))<<8 | uint32(galMultiply(p[ind30], p30))<<16 | uint32(galMultiply(p[ind31], p31))<<24
		p = p[chunk:]
	}
	h.h[0], h.h[1], h.h[2], h.h[3], h.h[4], h.h[5], h.h[6], h.h[7] = h0, h1, h2, h3, h4, h5, h6, h7
	return
}
