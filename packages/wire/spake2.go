package wire

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"filippo.io/nistec"
)

// p256Order is the P-256 group order n (prime; cofactor 1, so every point has order n).
var p256Order = elliptic.P256().Params().N

// RFC 9382 §4 fixed seed points for P-256, stored uncompressed (nistec decodes only the
// uncompressed SEC1 encoding). These are the decompressions of the compressed points in
// the RFC; the vector tests confirm they reproduce the RFC shares.
var (
	seedM = mustPoint("04886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20")
	seedN = mustPoint("04d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7")
)

func mustPoint(uncompressedHex string) *nistec.P256Point {
	b, err := hex.DecodeString(uncompressedHex)
	if err != nil {
		panic("wire: bad seed point hex: " + err.Error())
	}
	p, err := nistec.NewP256Point().SetBytes(b)
	if err != nil {
		panic("wire: bad seed point: " + err.Error())
	}
	return p
}

// seedFor is the seed point a role adds to its share (offerer→M, joiner→N).
func seedFor(role Role) *nistec.P256Point {
	if role == RoleOfferer {
		return seedM
	}
	return seedN
}

// peerSeedFor is the peer's seed point, subtracted to recover the shared point.
func peerSeedFor(role Role) *nistec.P256Point {
	if role == RoleOfferer {
		return seedN
	}
	return seedM
}

// Identities are the RFC transcript identity strings for the two parties.
type Identities struct {
	Offerer []byte
	Joiner  []byte
}

// DefaultIdentities are the SendArc identity strings bound into every handshake.
func DefaultIdentities() Identities {
	return Identities{Offerer: []byte(IdentityOfferer), Joiner: []byte(IdentityJoiner)}
}

func reduce(v *big.Int) *big.Int { return new(big.Int).Mod(v, p256Order) }

// scalarBytes encodes a reduced scalar as a 32-byte big-endian value (nistec's required
// form, and the SPAKE2 transcript's w encoding).
func scalarBytes(v *big.Int) []byte {
	out := make([]byte, 32)
	reduce(v).FillBytes(out)
	return out
}

// RandomScalar returns a uniformly random scalar in [1, n-1], suitable as the ephemeral
// SPAKE2 secret. It rejection-samples 48 bytes of randomness reduced mod n.
func RandomScalar() (*big.Int, error) {
	for {
		buf := make([]byte, 48)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		v := reduce(new(big.Int).SetBytes(buf))
		if v.Sign() != 0 {
			return v, nil
		}
	}
}

// PasswordToScalar maps a normalized invite code to the SPAKE2 password scalar w. This
// is SendArc-specific (RFC 9382 leaves the mapping to the application): w is HKDF over
// the UTF-8 code, then reduced mod n. 48 bytes before reduction leaves negligible bias.
func PasswordToScalar(normalizedCode string) (*big.Int, error) {
	bits, err := hkdfSHA256([]byte(normalizedCode), nil, []byte(infoSpake2W), spake2WHKDFBytes)
	if err != nil {
		return nil, err
	}
	return reduce(new(big.Int).SetBytes(bits)), nil
}

// ComputeShare computes this role's SPAKE2 share element w·seed + secret·G, uncompressed
// SEC1. Offerer → pA = w·M + x·G; joiner → pB = w·N + y·G.
func ComputeShare(role Role, w, secret *big.Int) ([]byte, error) {
	seedW, err := nistec.NewP256Point().ScalarMult(seedFor(role), scalarBytes(w))
	if err != nil {
		return nil, err
	}
	gS, err := nistec.NewP256Point().ScalarBaseMult(scalarBytes(secret))
	if err != nil {
		return nil, err
	}
	return nistec.NewP256Point().Add(seedW, gS).Bytes(), nil
}

// Spake2Output is the full result of finishing the SPAKE2 exchange, all as raw bytes.
type Spake2Output struct {
	K          []byte // shared group element K (uncompressed SEC1); never used directly as a key
	Transcript []byte // RFC transcript TT — input to the hash and both confirmation MACs
	Ke         []byte // shared secret Ke = Hash(TT)[0:16] — input to the SendArc key schedule
	Ka         []byte // confirmation-key material Ka = Hash(TT)[16:32]
	KcA        []byte // MAC key for the offerer's confirmation (RFC "A")
	KcB        []byte // MAC key for the joiner's confirmation (RFC "B")
	ConfirmA   []byte // offerer's confirmation MAC cA = HMAC(KcA, TT)
	ConfirmB   []byte // joiner's confirmation MAC cB = HMAC(KcB, TT)
}

// Finish completes the exchange with SendArc's identity strings.
func Finish(role Role, w, secret *big.Int, peerShare []byte) (*Spake2Output, error) {
	return finish(role, w, secret, peerShare, DefaultIdentities())
}

// finish completes the exchange from this role's secret and the peer's share element. It
// recovers the shared point K, assembles the RFC transcript, and derives Ke/Ka and both
// confirmation MACs. The identities let the RFC known-answer vectors override SendArc's.
func finish(role Role, w, secret *big.Int, peerShare []byte, ids Identities) (*Spake2Output, error) {
	peer, err := nistec.NewP256Point().SetBytes(peerShare)
	if err != nil {
		return nil, err
	}

	// Recover K = secret·(peerShare − w·peerSeed). Negate via the (n−w) scalar since
	// P-256 is prime-order: −w·P ≡ ((n−w) mod n)·P.
	negW := reduce(new(big.Int).Sub(p256Order, reduce(w)))
	negWpeerSeed, err := nistec.NewP256Point().ScalarMult(peerSeedFor(role), scalarBytes(negW))
	if err != nil {
		return nil, err
	}
	shared := nistec.NewP256Point().Add(peer, negWpeerSeed)
	k, err := nistec.NewP256Point().ScalarMult(shared, scalarBytes(secret))
	if err != nil {
		return nil, err
	}
	kBytes := k.Bytes()

	ownShare, err := ComputeShare(role, w, secret)
	if err != nil {
		return nil, err
	}
	pA, pB := ownShare, peerShare
	if role == RoleJoiner {
		pA, pB = peerShare, ownShare
	}

	transcript := concat(
		withLengthPrefix(ids.Offerer),
		withLengthPrefix(ids.Joiner),
		withLengthPrefix(pA),
		withLengthPrefix(pB),
		withLengthPrefix(kBytes),
		withLengthPrefix(scalarBytes(w)),
	)

	hash := sha256.Sum256(transcript)
	ke := hash[0:16]
	ka := hash[16:32]

	// KcA || KcB = HKDF(Ka, nil, "ConfirmationKeys", 32) — RFC 9382 §4.
	kc, err := hkdfSHA256(ka, nil, []byte(infoConfirmationKeys), 32)
	if err != nil {
		return nil, err
	}

	return &Spake2Output{
		K:          kBytes,
		Transcript: transcript,
		Ke:         append([]byte(nil), ke...),
		Ka:         append([]byte(nil), ka...),
		KcA:        kc[0:16],
		KcB:        kc[16:32],
		ConfirmA:   hmacSHA256(kc[0:16], transcript),
		ConfirmB:   hmacSHA256(kc[16:32], transcript),
	}, nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
