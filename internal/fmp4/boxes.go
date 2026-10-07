package fmp4

import (
	"encoding/binary"
	"math"
)

// box is one parsed ISO BMFF box. start is the absolute offset of the box
// header inside the buffer that was handed to parseBoxes, size is the total
// box size including the header, and data is the box payload.
type box struct {
	typ   string
	start int64
	size  int64
	hdr   int64
	data  []byte
}

// parseBoxes parses the concatenated boxes in buf. base is the absolute
// offset of buf inside the enclosing segment, used only for error messages
// and payload-range bookkeeping. seg and frag give the error context.
func parseBoxes(buf []byte, base int64, seg, frag int) ([]box, *AuditError) {
	var out []box
	off := int64(0)
	total := int64(len(buf))
	for off < total {
		remaining := total - off
		if remaining < 8 {
			return nil, errf(CodeBoxStructureInvalid, seg, frag,
				"truncated box header at offset %d (%d byte(s) left)", base+off, remaining)
		}
		size32 := binary.BigEndian.Uint32(buf[off:])
		typ := string(buf[off+4 : off+8])
		var size, hdr int64
		switch size32 {
		case 1:
			if remaining < 16 {
				return nil, errf(CodeBoxStructureInvalid, seg, frag,
					"truncated largesize box %q at offset %d", typ, base+off)
			}
			size64 := binary.BigEndian.Uint64(buf[off+8:])
			if size64 > math.MaxInt64 {
				return nil, errf(CodeBoxStructureInvalid, seg, frag,
					"box %q at offset %d has unsupported largesize %d", typ, base+off, size64)
			}
			size = int64(size64)
			hdr = 16
		case 0:
			// Box extends to the end of the enclosing data.
			size = remaining
			hdr = 8
		default:
			size = int64(size32)
			hdr = 8
		}
		if size < hdr {
			return nil, errf(CodeBoxStructureInvalid, seg, frag,
				"box %q at offset %d has invalid size %d", typ, base+off, size)
		}
		if size > remaining {
			return nil, errf(CodeBoxStructureInvalid, seg, frag,
				"box %q at offset %d exceeds available data (%d > %d)", typ, base+off, size, remaining)
		}
		out = append(out, box{
			typ:   typ,
			start: base + off,
			size:  size,
			hdr:   hdr,
			data:  buf[off+hdr : off+size],
		})
		off += size
	}
	return out, nil
}

func findBox(bs []box, typ string) *box {
	for i := range bs {
		if bs[i].typ == typ {
			return &bs[i]
		}
	}
	return nil
}

func findBoxes(bs []box, typ string) []box {
	var out []box
	for _, b := range bs {
		if b.typ == typ {
			out = append(out, b)
		}
	}
	return out
}

// fullBox strips the 4-byte version/flags header of a FullBox.
func fullBox(b *box, seg, frag int) (version uint8, flags uint32, body []byte, aerr *AuditError) {
	if len(b.data) < 4 {
		return 0, 0, nil, errf(CodeBoxStructureInvalid, seg, frag,
			"box %q too short for full-box header (%d byte(s))", b.typ, len(b.data))
	}
	version = b.data[0]
	flags = uint32(b.data[1])<<16 | uint32(b.data[2])<<8 | uint32(b.data[3])
	return version, flags, b.data[4:], nil
}

// cursor is a bounds-checked big-endian reader over a box payload.
type cursor struct {
	b   []byte
	off int
}

func (c *cursor) u32() (uint32, bool) {
	if c.off+4 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint32(c.b[c.off:])
	c.off += 4
	return v, true
}

func (c *cursor) u64() (uint64, bool) {
	if c.off+8 > len(c.b) {
		return 0, false
	}
	v := binary.BigEndian.Uint64(c.b[c.off:])
	c.off += 8
	return v, true
}

func (c *cursor) skip(n int) bool {
	if n < 0 || c.off+n > len(c.b) {
		return false
	}
	c.off += n
	return true
}
