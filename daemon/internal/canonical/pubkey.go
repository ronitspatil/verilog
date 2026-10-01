package canonical

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"filippo.io/edwards25519"
)

// ErrWeakPublicKey is wrapped by CheckPublicKey errors.
var ErrWeakPublicKey = errors.New("unsafe Ed25519 public key")

// PoPDomain prefixes the proof-of-possession message a new agent key signs
// before the key admin registers it: PoPDomain || agentKey (32 bytes) || pubkey.
const PoPDomain = "VeriLog/pop/v1\n"

// lMinus1 is the group order L minus one, as a canonical scalar.
var lMinus1 = func() *edwards25519.Scalar {
	b := []byte{
		0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
	}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(b)
	if err != nil {
		panic(err)
	}
	return s
}()

// CheckPublicKey rejects Ed25519 public keys that make signatures meaningless
// or ambiguous: wrong length, not a point on the curve, a non-canonical
// encoding, a point of small order (with such a key, signatures can be
// forged for any message without the private key), or a point with a
// small-order component (mixed order). Every key produced by honest key
// generation passes.
func CheckPublicKey(pub []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: must be %d bytes, got %d", ErrWeakPublicKey, ed25519.PublicKeySize, len(pub))
	}
	p, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return fmt.Errorf("%w: not a point on the curve", ErrWeakPublicKey)
	}
	if !bytes.Equal(p.Bytes(), pub) {
		return fmt.Errorf("%w: non-canonical point encoding", ErrWeakPublicKey)
	}
	identity := edwards25519.NewIdentityPoint()
	if new(edwards25519.Point).MultByCofactor(p).Equal(identity) == 1 {
		return fmt.Errorf("%w: point of small order", ErrWeakPublicKey)
	}
	// [L]P = [L-1]P + P must be the identity, or P has a small-order component.
	lp := new(edwards25519.Point).ScalarMult(lMinus1, p)
	if lp.Add(lp, p).Equal(identity) != 1 {
		return fmt.Errorf("%w: point of mixed order (not in the prime-order subgroup)", ErrWeakPublicKey)
	}
	return nil
}

// PoPMessage is the message signed as proof of possession of pub for the
// on-chain agent id agentKey (keccak256 of the agent id string).
func PoPMessage(agentKey Digest, pub []byte) []byte {
	msg := make([]byte, 0, len(PoPDomain)+len(agentKey)+len(pub))
	msg = append(msg, PoPDomain...)
	msg = append(msg, agentKey[:]...)
	return append(msg, pub...)
}

// SignPoP signs the proof-of-possession message for priv's public key.
func SignPoP(priv ed25519.PrivateKey, agentKey Digest) []byte {
	return ed25519.Sign(priv, PoPMessage(agentKey, priv.Public().(ed25519.PublicKey)))
}

// CheckKeyRegistration is what the key admin runs before registerAgentKey:
// pub must be a safe Ed25519 key (CheckPublicKey) and pop a valid signature
// by pub over PoPMessage(agentKey, pub), which shows the requester holds the
// private key and meant it for this agent.
func CheckKeyRegistration(agentKey Digest, pub, pop []byte) error {
	if err := CheckPublicKey(pub); err != nil {
		return err
	}
	if len(pop) != ed25519.SignatureSize {
		return fmt.Errorf("proof of possession must be %d bytes, got %d", ed25519.SignatureSize, len(pop))
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), PoPMessage(agentKey, pub), pop) {
		return errors.New("proof of possession does not verify for this agent id and public key")
	}
	return nil
}
