package wire

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

const vectorsDir = "../../test-vectors"

func loadVectors(t *testing.T, name string, v any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
}

func scalar(t *testing.T, h string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(h, 16)
	if !ok {
		t.Fatalf("bad scalar hex %q", h)
	}
	return n
}

func mustHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("bad hex %q: %v", h, err)
	}
	return b
}

// The RFC fixture uses lowercase single-letter keys, so each field carries an explicit
// json tag rather than relying on Go's exported-name matching.
type rfcVectorRaw struct {
	A        string `json:"A"`
	B        string `json:"B"`
	W        string `json:"w"`
	X        string `json:"x"`
	Y        string `json:"y"`
	PA       string `json:"pA"`
	PB       string `json:"pB"`
	K        string `json:"K"`
	TT       string `json:"TT"`
	Ke       string `json:"Ke"`
	Ka       string `json:"Ka"`
	KcA      string `json:"KcA"`
	KcB      string `json:"KcB"`
	ConfirmA string `json:"confirmA"`
	ConfirmB string `json:"confirmB"`
}

func TestSpake2RFC9382Vectors(t *testing.T) {
	var doc struct {
		Vectors []rfcVectorRaw `json:"vectors"`
	}
	loadVectors(t, "rfc9382-p256.json", &doc)
	if len(doc.Vectors) == 0 {
		t.Fatal("no RFC vectors loaded")
	}

	for i, v := range doc.Vectors {
		ids := Identities{Offerer: []byte(v.A), Joiner: []byte(v.B)}
		w := scalar(t, v.W)

		// Both shares reproduce.
		pA, err := ComputeShare(RoleOfferer, w, scalar(t, v.X))
		if err != nil {
			t.Fatalf("vector %d offerer share: %v", i, err)
		}
		if got := hex.EncodeToString(pA); got != v.PA {
			t.Errorf("vector %d pA = %s, want %s", i, got, v.PA)
		}
		pB, err := ComputeShare(RoleJoiner, w, scalar(t, v.Y))
		if err != nil {
			t.Fatalf("vector %d joiner share: %v", i, err)
		}
		if got := hex.EncodeToString(pB); got != v.PB {
			t.Errorf("vector %d pB = %s, want %s", i, got, v.PB)
		}

		// Offerer derives the full transcript, K, and MACs.
		out, err := finish(RoleOfferer, w, scalar(t, v.X), mustHex(t, v.PB), ids)
		if err != nil {
			t.Fatalf("vector %d offerer finish: %v", i, err)
		}
		checkHex(t, i, "K", out.K, v.K)
		checkHex(t, i, "TT", out.Transcript, v.TT)
		checkHex(t, i, "Ke", out.Ke, v.Ke)
		checkHex(t, i, "Ka", out.Ka, v.Ka)
		checkHex(t, i, "KcA", out.KcA, v.KcA)
		checkHex(t, i, "KcB", out.KcB, v.KcB)
		checkHex(t, i, "confirmA", out.ConfirmA, v.ConfirmA)
		checkHex(t, i, "confirmB", out.ConfirmB, v.ConfirmB)

		// Joiner derives the identical transcript and K.
		outB, err := finish(RoleJoiner, w, scalar(t, v.Y), mustHex(t, v.PA), ids)
		if err != nil {
			t.Fatalf("vector %d joiner finish: %v", i, err)
		}
		checkHex(t, i, "joiner K", outB.K, v.K)
		checkHex(t, i, "joiner TT", outB.Transcript, v.TT)
		if !bytes.Equal(out.Ke, outB.Ke) {
			t.Errorf("vector %d: offerer and joiner disagree on Ke", i)
		}
	}
}

func checkHex(t *testing.T, i int, field string, got []byte, want string) {
	t.Helper()
	if g := hex.EncodeToString(got); g != want {
		t.Errorf("vector %d %s = %s, want %s", i, field, g, want)
	}
}

type sendarcVectors struct {
	Code   string `json:"code"`
	Spake2 struct {
		W          string `json:"w"`
		X          string `json:"x"`
		Y          string `json:"y"`
		PA         string `json:"pA"`
		PB         string `json:"pB"`
		K          string `json:"K"`
		Transcript string `json:"transcript"`
		Ke         string `json:"Ke"`
		Ka         string `json:"Ka"`
		ConfirmA   string `json:"confirmA"`
		ConfirmB   string `json:"confirmB"`
	} `json:"spake2"`
	Keyschedule struct {
		Master  string `json:"master"`
		O2JKey  string `json:"o2jKey"`
		O2JSalt string `json:"o2jSalt"`
		J2OKey  string `json:"j2oKey"`
		J2OSalt string `json:"j2oSalt"`
	} `json:"keyschedule"`
	Aead struct {
		Direction     string `json:"direction"`
		Counter       uint64 `json:"counter"`
		HeaderHex     string `json:"headerHex"`
		PlaintextUtf8 string `json:"plaintextUtf8"`
		FrameHex      string `json:"frameHex"`
	} `json:"aead"`
}

func loadSendarc(t *testing.T) sendarcVectors {
	t.Helper()
	var sa sendarcVectors
	loadVectors(t, "sendarc-crypto.json", &sa)
	return sa
}

func TestSpake2SendarcVector(t *testing.T) {
	sa := loadSendarc(t)

	// w is derived from the invite code via the SendArc mapping.
	w, err := PasswordToScalar(sa.Code)
	if err != nil {
		t.Fatalf("PasswordToScalar: %v", err)
	}
	if got := hex.EncodeToString(scalarBytes(w)); got != sa.Spake2.W {
		t.Fatalf("w = %s, want %s", got, sa.Spake2.W)
	}

	pA, err := ComputeShare(RoleOfferer, w, scalar(t, sa.Spake2.X))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pA); got != sa.Spake2.PA {
		t.Errorf("pA = %s, want %s", got, sa.Spake2.PA)
	}
	pB, err := ComputeShare(RoleJoiner, w, scalar(t, sa.Spake2.Y))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(pB); got != sa.Spake2.PB {
		t.Errorf("pB = %s, want %s", got, sa.Spake2.PB)
	}

	out, err := Finish(RoleOfferer, w, scalar(t, sa.Spake2.X), mustHex(t, sa.Spake2.PB))
	if err != nil {
		t.Fatal(err)
	}
	checkHex(t, 0, "K", out.K, sa.Spake2.K)
	checkHex(t, 0, "transcript", out.Transcript, sa.Spake2.Transcript)
	checkHex(t, 0, "Ke", out.Ke, sa.Spake2.Ke)
	checkHex(t, 0, "confirmA", out.ConfirmA, sa.Spake2.ConfirmA)
	checkHex(t, 0, "confirmB", out.ConfirmB, sa.Spake2.ConfirmB)
}

func TestSpake2HandshakeAgrees(t *testing.T) {
	w, err := PasswordToScalar("4-brave-otter")
	if err != nil {
		t.Fatal(err)
	}
	x, _ := RandomScalar()
	y, _ := RandomScalar()
	pA, _ := ComputeShare(RoleOfferer, w, x)
	pB, _ := ComputeShare(RoleJoiner, w, y)
	a, err := Finish(RoleOfferer, w, x, pB)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Finish(RoleJoiner, w, y, pA)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.Ke, b.Ke) {
		t.Error("peers disagree on Ke")
	}
	if !bytes.Equal(a.Transcript, b.Transcript) {
		t.Error("peers disagree on transcript")
	}
	if !bytes.Equal(a.ConfirmB, b.ConfirmB) || !bytes.Equal(a.ConfirmA, b.ConfirmA) {
		t.Error("peers disagree on confirmations")
	}
}

func TestSpake2WrongCodeFailsClosed(t *testing.T) {
	wRight, _ := PasswordToScalar("4-brave-otter")
	wWrong, _ := PasswordToScalar("4-brave-otten")
	x, _ := RandomScalar()
	y, _ := RandomScalar()
	pA, _ := ComputeShare(RoleOfferer, wRight, x)
	pBWrong, _ := ComputeShare(RoleJoiner, wWrong, y)
	a, err := Finish(RoleOfferer, wRight, x, pBWrong)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Finish(RoleJoiner, wWrong, y, pA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Ke, b.Ke) {
		t.Error("wrong code still agreed on Ke")
	}
	if bytes.Equal(a.ConfirmB, b.ConfirmB) {
		t.Error("wrong code still produced matching confirmation")
	}
}

func TestSpake2FreshRandomness(t *testing.T) {
	w, _ := PasswordToScalar("4-brave-otter")
	derive := func() []byte {
		x, _ := RandomScalar()
		y, _ := RandomScalar()
		pB, _ := ComputeShare(RoleJoiner, w, y)
		a, err := Finish(RoleOfferer, w, x, pB)
		if err != nil {
			t.Fatal(err)
		}
		return a.Ke
	}
	if bytes.Equal(derive(), derive()) {
		t.Error("two sessions with the same code produced identical Ke")
	}
}

func TestSpake2RejectsOffCurveShare(t *testing.T) {
	w, _ := PasswordToScalar("4-brave-otter")
	x, _ := RandomScalar()
	garbage := make([]byte, 65)
	garbage[0] = 0x04 // claims uncompressed but coordinates are all zero → not on curve
	if _, err := Finish(RoleOfferer, w, x, garbage); err == nil {
		t.Error("expected off-curve peer share to be rejected")
	}
}
