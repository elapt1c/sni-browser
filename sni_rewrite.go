package main

import (
	"encoding/binary"
	"fmt"
)

// rewriteClientHelloSNI rewrites the Server Name Indication (SNI) hostname
// inside a TLS ClientHello record.
//
// It returns:
//   - out:      the (possibly rewritten) bytes to forward
//   - changed:  true if the SNI was actually replaced
//   - complete: true if a final decision was made (enough bytes were seen);
//     false means the input is a partial record and the caller should read
//     more bytes and retry.
//   - err:      non-nil only for a hard parse error on a complete record.
//
// If the record is not a ClientHello (or has no SNI extension), it returns
// the input unchanged with changed=false, complete=true.
func rewriteClientHelloSNI(data []byte, newSNI string) (out []byte, changed bool, complete bool, err error) {
	// TLS record header is 5 bytes.
	if len(data) < 5 {
		return data, false, false, nil
	}
	if data[0] != 0x16 { // not a handshake record
		return data, false, true, nil
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) < 5+recLen {
		return data, false, false, nil // incomplete record
	}

	// Handshake header (4 bytes) follows the record header.
	if recLen < 4 {
		return data, false, true, fmt.Errorf("handshake record too short (%d)", recLen)
	}
	if data[5] != 0x01 { // not ClientHello
		return data, false, true, nil
	}
	hsLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
	bodyOff := 9
	bodyEnd := bodyOff + hsLen
	if bodyEnd > 5+recLen {
		return data, false, true, fmt.Errorf("handshake length %d exceeds record %d", hsLen, recLen)
	}

	// Walk the ClientHello body to the extensions block.
	p := bodyOff
	// legacy_version (2)
	if p+2 > bodyEnd {
		return data, false, true, fmt.Errorf("truncated legacy_version")
	}
	p += 2
	// random (32)
	if p+32 > bodyEnd {
		return data, false, true, fmt.Errorf("truncated random")
	}
	p += 32
	// session_id<0..32>
	if p+1 > bodyEnd {
		return data, false, true, fmt.Errorf("truncated session_id length")
	}
	sidLen := int(data[p])
	p++
	if p+sidLen > bodyEnd {
		return data, false, true, fmt.Errorf("truncated session_id")
	}
	p += sidLen
	// cipher_suites<2..2^16-2>
	if p+2 > bodyEnd {
		return data, false, true, fmt.Errorf("truncated cipher_suites length")
	}
	csLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	p += 2
	if p+csLen > bodyEnd {
		return data, false, true, fmt.Errorf("truncated cipher_suites")
	}
	p += csLen
	// compression_methods<1..2^8-1>
	if p+1 > bodyEnd {
		return data, false, true, fmt.Errorf("truncated compression length")
	}
	compLen := int(data[p])
	p++
	if p+compLen > bodyEnd {
		return data, false, true, fmt.Errorf("truncated compression methods")
	}
	p += compLen

	// extensions<8..2^16-1> (optional)
	if p+2 > bodyEnd {
		return data, false, true, nil // no extensions → no SNI
	}
	extsLen := int(binary.BigEndian.Uint16(data[p : p+2]))
	extsLenOff := p
	extStart := p + 2
	extEnd := extStart + extsLen
	if extEnd > bodyEnd {
		return data, false, true, fmt.Errorf("truncated extensions block")
	}

	// Scan extensions for SNI (type 0x0000).
	q := extStart
	for q+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[q : q+2])
		extLen := int(binary.BigEndian.Uint16(data[q+2 : q+4]))
		if extType == 0x0000 {
			return rewriteSNIExtension(data, q, q+4+extLen, extEnd, newSNI, extsLenOff)
		}
		q += 4 + extLen
	}
	return data, false, true, nil // no SNI extension found
}

// rewriteSNIExtension rewrites the hostname in the SNI extension located at
// [extTypeOff, extDataEnd). extsLenOff is the offset of the 2-byte extensions
// total-length field; q is the extension-type offset.
func rewriteSNIExtension(data []byte, extTypeOff, extDataEnd int, extEnd int, newSNI string, extsLenOff int) ([]byte, bool, bool, error) {
	listLenOff := extTypeOff + 4
	if listLenOff+2 > extDataEnd {
		return data, false, true, fmt.Errorf("truncated SNI list length")
	}
	listLen := int(binary.BigEndian.Uint16(data[listLenOff : listLenOff+2]))
	listStart := listLenOff + 2
	listEnd := listStart + listLen
	if listEnd > extDataEnd || listEnd > extEnd {
		return data, false, true, fmt.Errorf("truncated SNI list")
	}
	if listStart+3 > listEnd {
		return data, false, true, nil // empty server name list
	}
	nameType := data[listStart]
	nameLenOff := listStart + 1
	nameLen := int(binary.BigEndian.Uint16(data[nameLenOff : nameLenOff+2]))
	nameStart := nameLenOff + 2
	nameEnd := nameStart + nameLen
	if nameType != 0x00 || nameEnd > listEnd {
		// Not a host_name, or malformed — leave untouched.
		return data, false, true, nil
	}
	if string(data[nameStart:nameEnd]) == newSNI {
		return data, false, true, nil // already equal
	}

	diff := len(newSNI) - nameLen

	// Build the rewritten buffer: replace [nameStart:nameEnd] with newSNI.
	out := make([]byte, 0, len(data)+diff)
	out = append(out, data[:nameStart]...)
	out = append(out, newSNI...)
	out = append(out, data[nameEnd:]...)

	// Adjust every length field that encloses the hostname. Offsets before
	// nameStart are unchanged; those after nameEnd shift by diff.
	adjust := func(off int, width int, val int) {
		if off >= nameEnd {
			off += diff
		}
		switch width {
		case 2:
			binary.BigEndian.PutUint16(out[off:off+2], uint16(val+diff))
		case 3:
			v := val + diff
			out[off] = byte(v >> 16)
			out[off+1] = byte(v >> 8)
			out[off+2] = byte(v)
		}
	}

	adjust(nameLenOff, 2, nameLen)                                                     // ServerName host_name length
	adjust(listLenOff, 2, listLen)                                                     // ServerNameList length
	adjust(extTypeOff+2, 2, extDataEnd-(extTypeOff+4))                                 // extension length
	adjust(extsLenOff, 2, int(binary.BigEndian.Uint16(data[extsLenOff:extsLenOff+2]))) // extensions length
	adjust(6, 3, int(data[6])<<16|int(data[7])<<8|int(data[8]))                        // handshake length
	adjust(3, 2, int(binary.BigEndian.Uint16(data[3:5])))                              // record length

	return out, true, true, nil
}
