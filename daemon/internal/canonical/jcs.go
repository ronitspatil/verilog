// Package canonical turns VeriLog events into deterministic bytes and hashes.
//
// Canonical JSON follows RFC 8785 (JSON Canonicalization Scheme):
//   - object members sorted by the UTF-16 code units of their names,
//   - no insignificant whitespace,
//   - strings emitted as UTF-8 with only the mandatory escapes
//     (quote, backslash, and control characters below U+0020),
//   - non-integer numbers serialized with the ECMAScript Number.toString
//     algorithm.
//
// Deviation from RFC 8785, on purpose: a number written as an integer literal
// (no fraction, no exponent) is emitted exactly as its decimal digits rather
// than being rounded through an IEEE-754 double. Audit logs carry ids and
// counters larger than 2^53 and rounding them would silently change the
// logged value. "-0" is normalized to "0".
//
// Duplicate object keys and invalid UTF-8 are rejected.
package canonical

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// ErrInvalidJSON is wrapped by every error caused by malformed input.
var ErrInvalidJSON = errors.New("invalid JSON")

// maxDepth bounds nesting so hostile payloads cannot exhaust the stack.
const maxDepth = 128

// CanonicalizeJSON parses a JSON document and returns its canonical form.
func CanonicalizeJSON(doc []byte) ([]byte, error) {
	v, err := parse(doc)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Grow(len(doc))
	if err := encode(&buf, v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// member is one key/value pair of a parsed object.
type member struct {
	key   string
	value any
}

// object preserves the parsed members; encode sorts them.
type object []member

// parse decodes doc into nil, bool, string, json.Number, []any or object.
func parse(doc []byte) (any, error) {
	if !utf8.Valid(doc) {
		return nil, fmt.Errorf("%w: not valid UTF-8", ErrInvalidJSON)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data after document", ErrInvalidJSON)
	}
	return v, nil
}

func parseValue(dec *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("%w: nesting deeper than %d", ErrInvalidJSON, maxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("%w: unexpected end of input", ErrInvalidJSON)
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := object{}
			seen := map[string]struct{}{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("%w: object key is not a string", ErrInvalidJSON)
				}
				if _, dup := seen[key]; dup {
					return nil, fmt.Errorf("%w: duplicate object key %q", ErrInvalidJSON, key)
				}
				seen[key] = struct{}{}
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj = append(obj, member{key: key, value: val})
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrInvalidJSON, err)
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("%w: unexpected delimiter %q", ErrInvalidJSON, t)
		}
	case string, bool, nil, json.Number:
		return t, nil
	default:
		return nil, fmt.Errorf("%w: unexpected token %T", ErrInvalidJSON, tok)
	}
}

func encode(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case string:
		writeString(buf, t)
	case json.Number:
		s, err := formatNumber(string(t))
		if err != nil {
			return err
		}
		buf.WriteString(s)
	case int:
		buf.WriteString(strconv.Itoa(t))
	case int64:
		buf.WriteString(strconv.FormatInt(t, 10))
	case uint64:
		buf.WriteString(strconv.FormatUint(t, 10))
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case object:
		sorted := make(object, len(t))
		copy(sorted, t)
		sort.Slice(sorted, func(i, j int) bool { return lessUTF16(sorted[i].key, sorted[j].key) })
		buf.WriteByte('{')
		for i, m := range sorted {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, m.key)
			buf.WriteByte(':')
			if err := encode(buf, m.value); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("canonical: unsupported value type %T", v)
	}
	return nil
}

// lessUTF16 orders strings by their UTF-16 code units, as RFC 8785 requires.
func lessUTF16(a, b string) bool {
	ua := utf16.Encode([]rune(a))
	ub := utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

const hexDigits = "0123456789abcdef"

func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			buf.WriteString(`\"`)
		case c == '\\':
			buf.WriteString(`\\`)
		case c == '\b':
			buf.WriteString(`\b`)
		case c == '\f':
			buf.WriteString(`\f`)
		case c == '\n':
			buf.WriteString(`\n`)
		case c == '\r':
			buf.WriteString(`\r`)
		case c == '\t':
			buf.WriteString(`\t`)
		case c < 0x20:
			buf.WriteString(`\u00`)
			buf.WriteByte(hexDigits[c>>4])
			buf.WriteByte(hexDigits[c&0xf])
		default:
			buf.WriteByte(c)
		}
	}
	buf.WriteByte('"')
}

// formatNumber canonicalizes one JSON number literal.
func formatNumber(lit string) (string, error) {
	if isIntegerLiteral(lit) {
		n, ok := new(big.Int).SetString(lit, 10)
		if !ok {
			return "", fmt.Errorf("%w: bad integer %q", ErrInvalidJSON, lit)
		}
		return n.String(), nil // big.Int prints -0 as 0 and drops leading zeros.
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		return "", fmt.Errorf("%w: number %q out of range", ErrInvalidJSON, lit)
	}
	return FormatES6Float(f)
}

func isIntegerLiteral(lit string) bool {
	return !strings.ContainsAny(lit, ".eE")
}

// FormatES6Float serializes f with the ECMAScript Number.prototype.toString
// algorithm (ECMA-262 7.1.12.1), as RFC 8785 section 3.2.2.3 requires.
func FormatES6Float(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: NaN and Infinity are not JSON", ErrInvalidJSON)
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// Shortest round-trip digits: "d.ddddde±XX".
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, err := strconv.Atoi(expStr)
	if err != nil {
		return "", err
	}
	k := len(digits)
	n := exp + 1 // position of the decimal point relative to the digits

	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		expSign := "+"
		if n-1 < 0 {
			expSign = "-"
		}
		absExp := n - 1
		if absExp < 0 {
			absExp = -absExp
		}
		if k == 1 {
			out = digits + "e" + expSign + strconv.Itoa(absExp)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(absExp)
		}
	}
	return sign + out, nil
}
