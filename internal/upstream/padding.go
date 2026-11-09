package upstream

import (
	"github.com/miekg/dns"
)

// paddingBlock is the block length for padded queries (RFC 8467 4.1, block-length padding:
// queries are padded to a multiple of 128 octets).
const paddingBlock = 128

// encryptedQuery prepares the wire message for an encrypted transport (DoT, DoH, DoH3, DoQ):
// a copy of req (the caller's message is never modified), the ID set to 0 when zeroID is
// true (RFC 8484 4.1, RFC 9250 4.2.1), and EDNS(0) padding (RFC 7830) to a multiple of 128
// octets. addedOPT reports whether the OPT record was added here (it is removed from the
// answer again, like for plain DNS).
func encryptedQuery(req *dns.Msg, zeroID bool) (m *dns.Msg, addedOPT bool) {
	m = req.Copy()
	if zeroID {
		m.Id = 0
	}
	addedOPT = padQuery(m)
	return m, addedOPT
}

// padQuery adds an EDNS(0) padding option to m so its wire length is a multiple of
// paddingBlock. An OPT record (UDP size 1232) is added when m has none; existing padding
// options are replaced. Returns true when the OPT record was added. When the message can
// not be packed it is left without padding (Pack fails later with a proper error).
func padQuery(m *dns.Msg) bool {
	added := false
	opt := m.IsEdns0()
	if opt == nil {
		m.SetEdns0(ednsUDPSize, false)
		opt = m.IsEdns0()
		added = true
	}
	opt.Option = withoutPadding(opt.Option)

	n := m.Len()
	if wire, err := m.Pack(); err == nil {
		n = len(wire) // exact length (Len may differ with compression)
	}
	// The option itself costs 4 octets (code + length) plus the padding.
	pad := (paddingBlock - (n+4)%paddingBlock) % paddingBlock
	if n+4+pad > dns.MaxMsgSize {
		return added
	}
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, pad)})
	return added
}

func withoutPadding(opts []dns.EDNS0) []dns.EDNS0 {
	out := make([]dns.EDNS0, 0, len(opts))
	for _, o := range opts {
		if _, ok := o.(*dns.EDNS0_PADDING); !ok {
			out = append(out, o)
		}
	}
	return out
}

// cleanAnswer restores the caller's ID, removes the OPT record when it was added for the
// upstream request, and strips padding from the answer (padding is a property of the
// encrypted hop, not of the answer for the client).
func cleanAnswer(resp *dns.Msg, id uint16, addedOPT bool) {
	resp.Id = id
	if addedOPT {
		resp.Extra = withoutOPT(resp.Extra)
		return
	}
	if opt := resp.IsEdns0(); opt != nil {
		opt.Option = withoutPadding(opt.Option)
	}
}
