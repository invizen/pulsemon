package main

import (
	"testing"
)

// refChecksum is an INDEPENDENT RFC 1071 one's-complement internet checksum:
// the canonical reference form — byte-by-byte big-endian 16-bit accumulation
// (no binary.Uint16, no shared code with icmpChecksum), odd-length trailing
// byte placed in the HIGH-order position (b[n-1] << 8), then a two-step
// carry fold. If icmpChecksum's odd-length padding or byte handling were
// wrong or architecture-dependent, it would disagree with this reference.
func refChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		w := uint32(b[i]) << 8
		if i+1 < len(b) {
			w |= uint32(b[i+1])
		}
		sum += w
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return ^uint16(sum)
}

// TestIcmpChecksumMatchesReference locks icmpChecksum against the
// independent RFC 1071 reference across every length 0..128 (both parities,
// including the 8-byte header / 32-byte message used in practice) plus
// large buffers, with pseudo-random byte values covering the whole 0..255
// range. This is the direct check on the "byte casting bug" claim: a wrong
// odd-length padding would show up here as a mismatch on odd lengths.
func TestIcmpChecksumMatchesReference(t *testing.T) {
	seed := make([]byte, 1000)
	for i := range seed {
		seed[i] = byte(i*37+11) ^ (byte(i>>3) + 1)
	}
	for n := 0; n <= 128; n++ {
		msg := seed[:n]
		if got, want := icmpChecksum(msg), refChecksum(msg); got != want {
			t.Errorf("icmpChecksum(%d bytes) = 0x%04x, reference = 0x%04x", n, got, want)
		}
	}
	for _, n := range []int{255, 256, 1000} {
		msg := seed[:n]
		if got, want := icmpChecksum(msg), refChecksum(msg); got != want {
			t.Errorf("icmpChecksum(%d bytes) = 0x%04x, reference = 0x%04x", n, got, want)
		}
	}
}

// TestIcmpChecksumOddLengthPadding pins the odd-length path specifically:
// a trailing lone byte must be summed as the high-order half-word. Hand-
// computable cases lock the semantics explicitly (not just
// implementation-vs-implementation).
func TestIcmpChecksumOddLengthPadding(t *testing.T) {
	// {0x12}: one half-word 0x1200; ^uint16(0x1200) = 0xedff.
	if got, want := icmpChecksum([]byte{0x12}), uint16(0xedff); got != want {
		t.Errorf("icmpChecksum({0x12}) = 0x%04x, want 0x%04x (trailing byte must be high-order)", got, want)
	}
	// {0x00, 0x12, 0x34}: first 16-bit word 0x0012, trailing odd byte 0x34 in
	// high order (0x3400); sum 0x3412; ^uint16(0x3412) = 0xcbed.
	if got, want := icmpChecksum([]byte{0x00, 0x12, 0x34}), uint16(0xcbed); got != want {
		t.Errorf("icmpChecksum({0x00,0x12,0x34}) = 0x%04x, want 0x%04x", got, want)
	}
	// The real 32-byte probe message (8 header + 24 payload) is even length
	// and its checksum must equal the reference — the exact message every
	// outgoing datagram ping carries.
	hdr := make([]byte, 8)
	msg := append(hdr, probePayload...)
	if got, want := icmpChecksum(msg), refChecksum(msg); got != want {
		t.Errorf("real 32-byte probe message: got 0x%04x want 0x%04x", got, want)
	}
}
