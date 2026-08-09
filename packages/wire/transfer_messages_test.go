package wire

import "testing"

// The exact JSON byte strings JavaScript's JSON.stringify produces for these shapes. Go must
// match them byte-for-byte (key order, no HTML escaping, no spaces) or a browser peer and a
// CLI peer cannot exchange control messages.
func TestEncodeControlWireBytes(t *testing.T) {
	cases := []struct {
		name string
		msg  ControlMsg
		want string
	}{
		{
			"manifest",
			NewManifest([]FileEntry{{
				Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
				LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
			}}, 10),
			`{"type":2,"files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}`,
		},
		{
			"manifest with transferId",
			&Manifest{
				Type: FrameManifest, TransferID: "0123456789abcdef0123456789abcdef",
				Files: []FileEntry{{
					Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
					LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
				}}, TotalSize: 10,
			},
			`{"type":2,"transferId":"0123456789abcdef0123456789abcdef","files":[{"idx":0,"name":"a.bin","size":10,"mime":"application/octet-stream","lastModified":5,"blockSize":8,"blocks":2,"fileDigest":"ab"}],"totalSize":10}`,
		},
		{"block_hash", NewBlockHash(0, 1, "ff"), `{"type":4,"fileIdx":0,"blockIdx":1,"sha256":"ff"}`},
		{"block_recv", NewBlockRecv(0, 1), `{"type":5,"fileIdx":0,"blockIdx":1}`},
		{"ack", NewAck(0, 1), `{"type":6,"fileIdx":0,"blockIdx":1}`},
		{"nack", NewNack(0, 2, NackMissing), `{"type":7,"fileIdx":0,"blockIdx":2,"reason":"missing"}`},
		{"pause", NewControl(ControlPause), `{"type":8,"op":"pause"}`},
		{"resume", NewControl(ControlResume), `{"type":8,"op":"resume"}`},
		{"cancel", NewControl(ControlCancel), `{"type":8,"op":"cancel"}`},
		{"complete", NewComplete("deadbeef"), `{"type":9,"fileDigest":"deadbeef"}`},
		{"done", NewDone(), `{"type":10}`},
		{"fail", NewFail(FailDigestMismatch), `{"type":11,"reason":"digest_mismatch"}`},
		{
			"resume_state",
			NewResumeState("0123456789abcdef0123456789abcdef", []ResumeFileState{{Idx: 0, HaveBlocks: 3}, {Idx: 1, HaveBlocks: 0}}),
			`{"type":12,"transferId":"0123456789abcdef0123456789abcdef","files":[{"idx":0,"haveBlocks":3},{"idx":1,"haveBlocks":0}]}`,
		},
	}
	for _, c := range cases {
		got, err := EncodeControl(c.msg)
		if err != nil {
			t.Fatalf("%s: encode: %v", c.name, err)
		}
		if string(got) != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.name, got, c.want)
		}
	}
}

// A filename with HTML-significant characters must not be \u-escaped, matching JS.
func TestEncodeControlNoHTMLEscaping(t *testing.T) {
	m := NewManifest([]FileEntry{{Name: "a&b<c>.txt", Mime: "text/plain", FileDigest: "x"}}, 0)
	got, err := EncodeControl(m)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"type":2,"files":[{"idx":0,"name":"a&b<c>.txt","size":0,"mime":"text/plain","lastModified":0,"blockSize":0,"blocks":0,"fileDigest":"x"}],"totalSize":0}`
	if string(got) != want {
		t.Errorf("HTML-escaping leaked:\n got  %s\n want %s", got, want)
	}
}

func TestDecodeControlRoundTrip(t *testing.T) {
	msgs := []ControlMsg{
		NewManifest([]FileEntry{{
			Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
			LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
		}}, 10),
		NewBlockHash(0, 1, "ff"),
		NewBlockRecv(0, 1),
		NewAck(0, 1),
		NewNack(0, 2, NackMissing),
		NewNack(0, 3, NackTimeout),
		NewControl(ControlPause),
		NewControl(ControlResume),
		NewControl(ControlCancel),
		NewComplete("deadbeef"),
		NewDone(),
		NewFail(FailDigestMismatch),
		&Manifest{
			Type: FrameManifest, TransferID: "0123456789abcdef0123456789abcdef",
			Files: []FileEntry{{
				Idx: 0, Name: "a.bin", Size: 10, Mime: "application/octet-stream",
				LastModified: 5, BlockSize: 8, Blocks: 2, FileDigest: "ab",
			}}, TotalSize: 10,
		},
		NewResumeState("0123456789abcdef0123456789abcdef", []ResumeFileState{{Idx: 0, HaveBlocks: 3}, {Idx: 1, HaveBlocks: 0}}),
	}
	for _, m := range msgs {
		enc, err := EncodeControl(m)
		if err != nil {
			t.Fatalf("encode %d: %v", m.FrameType(), err)
		}
		dec, err := DecodeControl(enc)
		if err != nil {
			t.Fatalf("decode %d: %v", m.FrameType(), err)
		}
		reenc, err := EncodeControl(dec)
		if err != nil {
			t.Fatalf("re-encode %d: %v", m.FrameType(), err)
		}
		if string(reenc) != string(enc) {
			t.Errorf("type %d not stable: %s != %s", m.FrameType(), reenc, enc)
		}
	}
}

// A payload the TS decoder produced must decode here to the same values (decode-side interop).
func TestDecodeControlFromTSShapes(t *testing.T) {
	m, err := DecodeControl([]byte(`{"type":7,"fileIdx":2,"blockIdx":7,"reason":"timeout"}`))
	if err != nil {
		t.Fatal(err)
	}
	nack, ok := m.(*Nack)
	if !ok || nack.FileIdx != 2 || nack.BlockIdx != 7 || nack.Reason != NackTimeout {
		t.Fatalf("decoded nack = %#v", m)
	}

	m, err = DecodeControl([]byte(`{"type":12,"transferId":"abc123","files":[{"idx":0,"haveBlocks":5},{"idx":1,"haveBlocks":0}]}`))
	if err != nil {
		t.Fatal(err)
	}
	rs, ok := m.(*ResumeState)
	if !ok || rs.TransferID != "abc123" || len(rs.Files) != 2 ||
		rs.Files[0] != (ResumeFileState{Idx: 0, HaveBlocks: 5}) || rs.Files[1] != (ResumeFileState{Idx: 1, HaveBlocks: 0}) {
		t.Fatalf("decoded resume_state = %#v", m)
	}

	// A manifest carrying a transferId decodes with the id preserved.
	m, err = DecodeControl([]byte(`{"type":2,"transferId":"abc123","files":[{"idx":0,"name":"a","size":0,"mime":"x","lastModified":0,"blockSize":1,"blocks":0,"fileDigest":"y"}],"totalSize":0}`))
	if err != nil {
		t.Fatal(err)
	}
	if man, ok := m.(*Manifest); !ok || man.TransferID != "abc123" {
		t.Fatalf("decoded manifest transferId = %#v", m)
	}
}

func TestDecodeControlRejectsMalformed(t *testing.T) {
	bad := []string{
		`{{`,           // invalid JSON
		`{"type":999}`, // out-of-range type
		`{"type":263,"fileIdx":0,"blockIdx":1,"reason":"missing"}`, // must not wrap to nack
		`{"type":11,"reason":"nope"}`,                              // bad fail reason
		`{"type":7,"fileIdx":0,"blockIdx":1,"reason":"bad"}`,       // bad nack reason
		`{"type":8,"op":"stop"}`,                                   // bad control operation
		`{"type":9}`,                                               // complete missing fileDigest
		`{"type":2,"files":[],"totalSize":0}`,                      // empty manifest files
		`{"type":4,"fileIdx":0}`,                                   // block_hash missing sha256/blockIdx
		`{"type":12,"files":[{"idx":0,"haveBlocks":0}]}`,           // resume_state missing transferId
		`{"type":12,"transferId":"x","files":[]}`,                  // resume_state empty files
		`{"type":12,"transferId":"x","files":[{"idx":0}]}`,         // resume file missing haveBlocks
		`{"fileIdx":0}`,                                            // missing type
	}
	for _, s := range bad {
		if _, err := DecodeControl([]byte(s)); err == nil {
			t.Errorf("expected error decoding %q", s)
		}
	}
}
