package canonical

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrNotCanonical is returned by ParseCanonicalEvent when a document parses
// as an event but is not byte-for-byte its canonical form.
var ErrNotCanonical = errors.New("event is not in canonical form")

// ParseCanonicalEvent parses an event document that must be exactly the
// canonical bytes of the event, optionally followed by one "\n" (as written
// by verilog-verify export). It returns the event and its canonical bytes.
//
// Verification hashes and checks the canonical bytes, so accepting any other
// spelling (reordered members, whitespace, escapes, a number written as
// 9007199254740993.0 where 9007199254740992 was signed) would let an evidence
// file display content that differs from what the agent signed.
func ParseCanonicalEvent(doc []byte) (Event, []byte, error) {
	ev, err := ParseEvent(doc)
	if err != nil {
		return Event{}, nil, err
	}
	canon, err := ev.Canonical()
	if err != nil {
		return Event{}, nil, err
	}
	if !bytes.Equal(bytes.TrimSuffix(doc, []byte("\n")), canon) {
		return ev, canon, fmt.Errorf("%w: the document differs from the canonical bytes that are hashed and signed", ErrNotCanonical)
	}
	return ev, canon, nil
}
