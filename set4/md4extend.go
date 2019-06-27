package set4

import (
	"bytes"
	"encoding/binary"
)

// Implementation copied from cryto/md4

const (
	_Chunk = 64
	_Init0 = 0x67452301
	_Init1 = 0xEFCDAB89
	_Init2 = 0x98BADCFE
	_Init3 = 0x10325476
)

var shift1 = []uint{3, 7, 11, 19}
var shift2 = []uint{3, 5, 9, 13}
var shift3 = []uint{3, 9, 11, 15}

var xIndex2 = []uint{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
var xIndex3 = []uint{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}

// md4Digest represents the partial evaluation of a checksum.
type md4Digest struct {
	s   [4]uint32
	x   [_Chunk]byte
	nx  int
	len uint64
}

// MD4Extension works from code primarily copied from crypto/md4, but allows setting the internal state of
// the algorithm allowing for length-extension attacks
func MD4Extension(mac, oldMessage, extension []byte) []byte {
	d := new(md4Digest)

	// MD4 writes are little Endian
	d.s[0] = binary.LittleEndian.Uint32(mac[0:])
	d.s[1] = binary.LittleEndian.Uint32(mac[4:])
	d.s[2] = binary.LittleEndian.Uint32(mac[8:])
	d.s[3] = binary.LittleEndian.Uint32(mac[12:])

	oldPadding := messagePaddingMD4(oldMessage)
	d.len = uint64(len(oldMessage) + len(oldPadding))
	d.Write(extension)

	return d.Sum(nil)
}

func messagePaddingMD4(input []byte) []byte {
	padding := []byte{0x80} // firstly, we must stick a '1' bit as the first character of padding

	// Then, we must calculate how many zero bits we need to add so that:
	// message length + 1 bit + zero bits = 448
	lenZeroBytes := 56 - ((len(input) + 1) % 64)
	if (len(input) % 64) > 56 {
		lenZeroBytes += 64
	}

	padding = append(padding, bytes.Repeat([]byte{0x00}, lenZeroBytes)...) // add our zero bytes

	// calculate our message length in bits...
	messageLen := make([]byte, 8)
	len := len(input) << 3
	for i := uint(0); i < 8; i++ {
		messageLen[i] = byte(len >> (8 * i))
	}

	return append(padding, messageLen...) // ... add our message length at the end of our padding
}

func (d *md4Digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.len += uint64(nn)
	if d.nx > 0 {
		n := len(p)
		if n > _Chunk-d.nx {
			n = _Chunk - d.nx
		}
		for i := 0; i < n; i++ {
			d.x[d.nx+i] = p[i]
		}
		d.nx += n
		if d.nx == _Chunk {
			_Block(d, d.x[0:])
			d.nx = 0
		}
		p = p[n:]
	}
	n := _Block(d, p)
	p = p[n:]
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

func (d0 *md4Digest) Sum(in []byte) []byte {
	// Make a copy of d0, so that caller can keep writing and summing.
	d := new(md4Digest)
	*d = *d0

	// Padding.  Add a 1 bit and 0 bits until 56 bytes mod 64.
	len := d.len
	var tmp [64]byte
	tmp[0] = 0x80
	if len%64 < 56 {
		d.Write(tmp[0 : 56-len%64])
	} else {
		d.Write(tmp[0 : 64+56-len%64])
	}

	// Length in bits.
	len <<= 3
	for i := uint(0); i < 8; i++ {
		tmp[i] = byte(len >> (8 * i))
	}
	d.Write(tmp[0:8])

	if d.nx != 0 {
		panic("d.nx != 0")
	}

	for _, s := range d.s {
		in = append(in, byte(s>>0))
		in = append(in, byte(s>>8))
		in = append(in, byte(s>>16))
		in = append(in, byte(s>>24))
	}
	return in
}

func _Block(dig *md4Digest, p []byte) int {
	a := dig.s[0]
	b := dig.s[1]
	c := dig.s[2]
	d := dig.s[3]
	n := 0
	var X [16]uint32
	for len(p) >= _Chunk {
		aa, bb, cc, dd := a, b, c, d

		j := 0
		for i := 0; i < 16; i++ {
			X[i] = uint32(p[j]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
			j += 4
		}

		// If this needs to be made faster in the future,
		// the usual trick is to unroll each of these
		// loops by a factor of 4; that lets you replace
		// the shift[] lookups with constants and,
		// with suitable variable renaming in each
		// unrolled body, delete the a, b, c, d = d, a, b, c
		// (or you can let the optimizer do the renaming).
		//
		// The index variables are uint so that % by a power
		// of two can be optimized easily by a compiler.

		// Round 1.
		for i := uint(0); i < 16; i++ {
			x := i
			s := shift1[i%4]
			f := ((c ^ d) & b) ^ d
			a += f + X[x]
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 2.
		for i := uint(0); i < 16; i++ {
			x := xIndex2[i]
			s := shift2[i%4]
			g := (b & c) | (b & d) | (c & d)
			a += g + X[x] + 0x5a827999
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		// Round 3.
		for i := uint(0); i < 16; i++ {
			x := xIndex3[i]
			s := shift3[i%4]
			h := b ^ c ^ d
			a += h + X[x] + 0x6ed9eba1
			a = a<<s | a>>(32-s)
			a, b, c, d = d, a, b, c
		}

		a += aa
		b += bb
		c += cc
		d += dd

		p = p[_Chunk:]
		n += _Chunk
	}

	dig.s[0] = a
	dig.s[1] = b
	dig.s[2] = c
	dig.s[3] = d
	return n
}
