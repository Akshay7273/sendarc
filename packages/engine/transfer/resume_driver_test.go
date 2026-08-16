package transfer

// V13-PR08 cross-session resume regression tests (driver level, deterministic).
//
// The critical invariant these tests pin: durable progress from a PREVIOUS authenticated
// session may be reused ONLY after successful resume-auth-v1 continuity authentication.
// A fresh invite/rendezvous code authenticates the NEW session; it does NOT by itself
// prove continuity with the original transfer peer. Every fresh-session path that would
// otherwise skip old blocks merely because transferId + fingerprint match must fail
// closed.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/engine/rendezvous"
	"github.com/sendbeam/wire"
)

// result pairs a driver Run outcome with its error, mirroring the local helper type used
// across the other driver test files.
type result struct {
	out *Outcome
	err error
}

// resumeLegSpec configures one driver leg for the resume regression tests.
type resumeLegSpec struct {
	interrupt    bool
	sendResume   *ResumeContext
	recvResume   *ResumeContext
	sendCaps     *rendezvous.Caps
	recvCaps     *rendezvous.Caps
	onSendResume func(ResumeResult)
	onRecvResume func(ResumeResult)
	// recvProgress counts acknowledged bytes on the receiver (0 for a zero-byte resume).
	recvProgress func(int64)
}

// runResumeLeg runs one send+receive pair through the real driver.
func runResumeLeg(ctx context.Context, t *testing.T, senderStore *SenderStore, outDir string, args []string, ls resumeLegSpec) (send, recv result, id string, reused bool) {
	t.Helper()
	hub := newRelay()
	sources, _, err := NewOSFileSources(args)
	if err != nil {
		t.Fatal(err)
	}
	var hook func(wire.Manifest) error
	id, hook, reused, err = PrepareSender(senderStore, args, sources)
	if err != nil {
		t.Fatal(err)
	}
	legCtx, legCancel := context.WithCancel(ctx)
	defer legCancel()
	firstProgress := make(chan struct{})
	var once sync.Once
	if ls.interrupt {
		go func() {
			select {
			case <-firstProgress:
				legCancel()
			case <-legCtx.Done():
			}
		}()
	}
	sendDone := make(chan result, 1)
	recvDone := make(chan result, 1)
	go func() {
		out, err := Run(legCtx, hub.off, Spec{
			Session:        rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo", LocalCaps: ls.sendCaps},
			Sources:        sources,
			TransferID:     id,
			OnSendManifest: hook,
			OnResumeCredential: func(manifest wire.Manifest, resumeRoot []byte) error {
				return senderStore.AttachResumeSecret(manifest, resumeRoot, !reused)
			},
			Resume:     ls.sendResume,
			OnResume:   ls.onSendResume,
			ICEServers: []webrtc.ICEServer{},
		})
		sendDone <- result{out, err}
	}()
	go func() {
		out, err := Run(legCtx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo", LocalCaps: ls.recvCaps},
			DestDir:    outDir,
			Resume:     ls.recvResume,
			OnResume:   ls.onRecvResume,
			ICEServers: []webrtc.ICEServer{},
			OnProgress: func(n int64) {
				if ls.recvProgress != nil {
					ls.recvProgress(n)
				}
				if ls.interrupt {
					once.Do(func() { close(firstProgress) })
				}
			},
		})
		recvDone <- result{out, err}
	}()
	// Wait for whichever side settles first. When that side FAILED, the transfer can no
	// longer succeed, so cancel the leg context to unblock the peer — this mirrors
	// production, where a failing peer tears down its signaling socket and the surviving
	// side's read loop surfaces the closure as a cancelled transfer. A successful first
	// result needs no cancel: the peer completes on its own.
	select {
	case s := <-sendDone:
		send = s
		if s.err != nil {
			legCancel()
		}
		recv = <-recvDone
	case r := <-recvDone:
		recv = r
		if r.err != nil {
			legCancel()
		}
		send = <-sendDone
	}
	return send, recv, id, reused
}

// seedInterruptedTransfer runs a real interrupted leg so BOTH peers persist the transfer
// id, the manifest fingerprint, and the matching resume credential. It returns the sender
// record and the receiver journal.
func seedInterruptedTransfer(t *testing.T, senderStore *SenderStore, outDir string, args []string) (SenderRecord, wire.DurableJournal) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	send, recv, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		interrupt: true,
		sendCaps:  resumeCaps(),
		recvCaps:  resumeCaps(),
	})
	if send.err == nil || recv.err == nil {
		t.Fatalf("seed leg unexpectedly succeeded: send=%v recv=%v", send.err, recv.err)
	}
	srec, ok, err := senderStore.Lookup(PathKey(args))
	if err != nil || !ok {
		t.Fatalf("sender record missing: ok=%v err=%v", ok, err)
	}
	if srec.ResumeSecret == nil {
		t.Fatal("sender record must carry the resume credential")
	}
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	j, ok, err := recvStore.LoadJournal(srec.TransferID)
	if err != nil || !ok {
		t.Fatalf("receiver journal missing: ok=%v err=%v", ok, err)
	}
	if j.ResumeSecret == nil {
		t.Fatal("receiver journal must carry the resume credential")
	}
	return srec, j
}

// resumeCaps advertises resume-auth-v1 (the CLI does this only on a peer that can
// actually authenticate a resume).
func resumeCaps() *rendezvous.Caps {
	c := rendezvous.DefaultCaps()
	c.Features = append(c.Features, wire.ResumeAuthCapability)
	return &c
}

func plainCaps() *rendezvous.Caps {
	c := rendezvous.DefaultCaps()
	return &c
}

func decodeJournalSecret(t *testing.T, j *wire.JournalResumeSecret) []byte {
	t.Helper()
	secret, err := wire.DecodeResumeSecretEnvelope(&wire.ResumeSecretEnvelope{Version: j.Version, Value: j.Value})
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func decodeRecordSecret(t *testing.T, e *wire.ResumeSecretEnvelope) []byte {
	t.Helper()
	secret, err := wire.DecodeResumeSecretEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

// TestDriverFreshSessionCannotSkipOldBlocksWithoutResumeAuth is the V13-PR08 critical
// audit regression: a fresh rendezvous that reuses the transferId + matching fingerprint
// MUST NOT skip old blocks when resume-auth was never performed. This holds even when the
// sender (miswired or malicious) reuses the id without any resume context: the receiver
// fails closed and nothing is transferred or deleted.
func TestDriverFreshSessionCannotSkipOldBlocksWithoutResumeAuth(t *testing.T) {
	senderStore := testSenderStore(t)
	outDir := t.TempDir()
	srcDir := t.TempDir()
	payload := make([]byte, 8<<20)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{srcPath}
	srec, j := seedInterruptedTransfer(t, senderStore, outDir, args)
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	committedBefore := before[0].CommittedBytes

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Variant C: the persisted resume role does NOT match the actual rendezvous role (the
	// sender record was somehow armed on a session whose role is not offerer). The driver
	// must fail closed on the role mismatch before anything is sent — never silently
	// ignore a mismatched persisted/host role.
	sendC, recvC, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: &ResumeContext{
			TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint,
			Role: wire.RoleJoiner, ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		},
		sendCaps: resumeCaps(),
		recvCaps: resumeCaps(),
	})
	if sendC.err == nil || !bytes.Contains([]byte(sendC.err.Error()), []byte("resume role mismatch")) {
		t.Fatalf("sender must fail closed on a resume role mismatch, got %v", sendC.err)
	}
	if recvC.err == nil {
		t.Fatal("receiver must not complete when the sender's role binding fails")
	}

	// Variant A: the sender reuses its record (Spec.Resume set, capability advertised) but
	// the receiver joins as a plain fresh receive (no resume context, no capability). The
	// sender must refuse to reuse the id before anything is sent. runResumeLeg cancels the
	// leg the moment the sender's refusal lands, unblocking the plain fresh receiver
	// (production surfaces the same via the signaling socket close).
	sendA, recvA, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: &ResumeContext{
			TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint,
			Role: wire.RoleOfferer, ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		},
		sendCaps: resumeCaps(),
		recvCaps: plainCaps(),
	})
	if sendA.err == nil || !bytes.Contains([]byte(sendA.err.Error()), []byte("resume-auth-v1")) {
		t.Fatalf("sender must refuse to reuse the id without a capable peer, got %v", sendA.err)
	}
	if recvA.err == nil {
		t.Fatal("receiver must not complete without resume auth")
	}

	// Variant B: the sender (miswired) reuses the id WITHOUT any resume context. The
	// receiver still fails closed at its journal — a fresh session can never skip old
	// blocks merely because transferId + fingerprint match.
	sendB, recvB, idB, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendCaps: plainCaps(),
		recvCaps: plainCaps(),
	})
	if idB != srec.TransferID {
		t.Fatalf("sender did not reuse the id: %q != %q", idB, srec.TransferID)
	}
	if sendB.err == nil {
		t.Fatal("variant B send must fail")
	}
	if recvB.err == nil || !bytes.Contains([]byte(recvB.err.Error()), []byte("authenticated resume")) {
		t.Fatalf("receiver must fail closed with guidance, got %v", recvB.err)
	}
	if bytes.Contains([]byte(recvB.err.Error()), []byte("nothing was received or deleted")) == false {
		t.Fatalf("receiver guidance must state nothing was transferred: %v", recvB.err)
	}

	// Fail closed means nothing moved and nothing was deleted.
	after, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].CommittedBytes != committedBefore {
		t.Fatalf("journal changed across an unauthenticated fresh session: before=%d after=%#v", committedBefore, after)
	}
	if _, ok, err := senderStore.Lookup(PathKey(args)); err != nil || !ok {
		t.Fatalf("sender record must be preserved: ok=%v err=%v", ok, err)
	}
	if _, err := os.Stat(filepath.Join(outDir, "payload.bin")); err == nil {
		t.Fatal("final file must not exist after an unauthenticated fresh session")
	}
	_ = j
}

// TestDriverReceiverResumeWithoutCapableSenderFallsBackFresh pins the receiver side of a
// non-resume join: a receiver that pre-selected an interrupted journal but joins a sender
// that started FRESH must receive fresh (a different transfer id) and leave its own
// interrupted state untouched.
func TestDriverReceiverResumeWithoutCapableSenderFallsBackFresh(t *testing.T) {
	senderStore := testSenderStore(t)
	outDir := t.TempDir()
	srcDir := t.TempDir()
	payload := make([]byte, 4<<20)
	for i := range payload {
		payload[i] = byte(i*3 + 1)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{srcPath}
	srec, j := seedInterruptedTransfer(t, senderStore, outDir, args)
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	committedBefore := before[0].CommittedBytes

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	// The sender must be genuinely fresh: discard its record so PrepareSender mints a new
	// id and the send path does not advertise resume-auth-v1 (no credential loaded).
	if err := senderStore.Discard(srec.TransferID); err != nil {
		t.Fatal(err)
	}
	var skipped bool
	send2, recv2, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		recvResume: &ResumeContext{
			TransferID: j.TransferID, ManifestFingerprint: j.ManifestFingerprint,
			Role: wire.RoleJoiner, ResumeSecret: decodeJournalSecret(t, j.ResumeSecret),
		},
		recvCaps: resumeCaps(),
		onRecvResume: func(r ResumeResult) {
			if r.Skipped {
				skipped = true
			}
		},
		sendCaps: plainCaps(),
	})
	if send2.err != nil || recv2.err != nil {
		t.Fatalf("fresh leg must complete: send=%v recv=%v", send2.err, recv2.err)
	}
	if !skipped {
		t.Fatal("receiver must report the skipped resume (fresh sender)")
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("fresh receive must deliver the whole file")
	}
	// The pre-selected interrupted journal is untouched (still resumable later).
	after, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].TransferID != j.TransferID || after[0].CommittedBytes != committedBefore {
		t.Fatalf("pre-selected journal changed by a fresh receive: %#v", after)
	}
}

// TestDriverResumeAuthFailurePreservesStateAndAllowsRetry pins the failure semantics:
// a failed resume-auth (here: one peer's credential does not match) preserves the sender
// record and the receiver journal exactly, and a LATER fresh attempt with the correct
// credential and fresh nonces succeeds.
func TestDriverResumeAuthFailurePreservesStateAndAllowsRetry(t *testing.T) {
	senderStore := testSenderStore(t)
	outDir := t.TempDir()
	srcDir := t.TempDir()
	payload := make([]byte, 8<<20)
	for i := range payload {
		payload[i] = byte(i*11 + 9)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{srcPath}
	srec, j := seedInterruptedTransfer(t, senderStore, outDir, args)
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	committedBefore := before[0].CommittedBytes

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	// Attempt 1: the receiver's journal was tampered (a DIFFERENT secret). The handshake
	// fails closed on both sides; nothing moves.
	wrong := make([]byte, 32)
	for i := range wrong {
		wrong[i] = byte(i + 1)
	}
	send1, recv1, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: &ResumeContext{
			TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint,
			Role: wire.RoleOfferer, ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		},
		recvResume: &ResumeContext{
			TransferID: j.TransferID, ManifestFingerprint: j.ManifestFingerprint,
			Role: wire.RoleJoiner, ResumeSecret: wrong,
		},
		sendCaps: resumeCaps(),
		recvCaps: resumeCaps(),
	})
	if send1.err == nil || recv1.err == nil {
		t.Fatalf("wrong-secret attempt must fail: send=%v recv=%v", send1.err, recv1.err)
	}
	after, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].CommittedBytes != committedBefore {
		t.Fatalf("failed auth changed the journal: before=%d after=%#v", committedBefore, after)
	}
	if _, ok, err := senderStore.Lookup(PathKey(args)); err != nil || !ok {
		t.Fatalf("failed auth removed the sender record: ok=%v err=%v", ok, err)
	}

	// Attempt 2: the correct credential, fresh nonces (the driver uses crypto/rand). The
	// failed attempt consumed nothing; this one completes.
	send2, recv2, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: &ResumeContext{
			TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint,
			Role: wire.RoleOfferer, ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		},
		recvResume: &ResumeContext{
			TransferID: j.TransferID, ManifestFingerprint: j.ManifestFingerprint,
			Role: wire.RoleJoiner, ResumeSecret: decodeJournalSecret(t, j.ResumeSecret),
		},
		sendCaps: resumeCaps(),
		recvCaps: resumeCaps(),
	})
	if send2.err != nil || recv2.err != nil {
		t.Fatalf("retry after failed auth: send=%v recv=%v", send2.err, recv2.err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed file differs from source")
	}
}

// TestDriverResumeTransfersZeroBytesWhenAllCommitted pins the lost-final-Done behavior:
// when every block was already durable before the restart, the authenticated resume sends
// NO block data, whole-file verification still runs, and the receive finalizes.
func TestDriverResumeTransfersZeroBytesWhenAllCommitted(t *testing.T) {
	senderStore := testSenderStore(t)
	outDir := t.TempDir()
	srcDir := t.TempDir()
	// The wire layer builds the manifest with the NEGOTIATED block size (both peers
	// announce defaultBlockBytes = 1 MiB in these tests), and the record/journal
	// fingerprints bind that geometry — so the seeded manifest must use the same size or
	// the resume leg sees a fingerprint mismatch.
	blockSize := 1024 * 1024
	payload := make([]byte, 4*blockSize)
	for i := range payload {
		payload[i] = byte(i*17 + 2)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{srcPath}

	// Seed the state: a sender record + a receiver journal whose checkpoint claims ALL
	// blocks (the transfer was durable before the restart, but never finalized).
	sources, _, err := NewOSFileSources(args)
	if err != nil {
		t.Fatal(err)
	}
	_, hook, reused, err := PrepareSender(senderStore, args, sources)
	if err != nil || reused {
		t.Fatalf("fresh PrepareSender: reused=%v err=%v", reused, err)
	}
	// The manifest must carry the REAL source meta: the resume leg's PrepareSender runs
	// cheapSourceCheck against the live file and rejects a record whose mtime differs.
	meta := sources[0].Meta()
	manifest := wire.NewManifest([]wire.FileEntry{{
		Idx: 0, Name: meta.Name, Size: meta.Size, Mime: meta.Mime,
		LastModified: meta.LastModified, BlockSize: blockSize, Blocks: len(payload) / blockSize,
		FileDigest: sha256Hex(payload),
	}}, int64(len(payload)))
	// The wire layer mints the transfer id exactly like this when a fresh record is
	// created; the manifest is what binds the id to the record at persist time. The
	// fingerprint binds the id too, so it must be computed AFTER the id is set.
	id := newTransferID()
	manifest.TransferID = id
	validated, err := wire.ValidateManifest(*manifest)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := wire.ManifestFingerprint(validated)
	if err != nil {
		t.Fatal(err)
	}
	if err := hook(*manifest); err != nil {
		t.Fatal(err)
	}
	// Attach the credential the way the ORIGINAL session would have (fresh record).
	root, err := wire.ResumeRoot(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if err := senderStore.AttachResumeSecret(*manifest, root, true); err != nil {
		t.Fatal(err)
	}
	// Reload the record AFTER the credential attach — the pre-attach copy is stale.
	srec, ok, err := senderStore.Lookup(PathKey(args))
	if err != nil || !ok {
		t.Fatalf("sender record missing: ok=%v err=%v", ok, err)
	}
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	dest, err := NewDurableDestination(outDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := dest.Prepare(*manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(validated.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(payload); off += blockSize {
		if err := sink.Write(int64(off), payload[off:off+blockSize]); err != nil {
			t.Fatal(err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	// Attach the matching credential to the journal (fresh session-created journal).
	if err := dest.AttachResumeSecret(*manifest, root); err != nil {
		t.Fatal(err)
	}
	j, ok, err := recvStore.LoadJournal(id)
	if err != nil || !ok {
		t.Fatalf("journal missing: ok=%v err=%v", ok, err)
	}
	if j.Files[0].CommittedBlocks != len(payload)/blockSize {
		t.Fatalf("seeded checkpoint not full: %d blocks", j.Files[0].CommittedBlocks)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	recvProgressTotal := int64(0)
	send, recv, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: &ResumeContext{
			TransferID: id, ManifestFingerprint: fp, Role: wire.RoleOfferer,
			ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		},
		recvResume: &ResumeContext{
			TransferID: id, ManifestFingerprint: fp, Role: wire.RoleJoiner,
			ResumeSecret: decodeJournalSecret(t, j.ResumeSecret),
		},
		sendCaps: resumeCaps(),
		recvCaps: resumeCaps(),
		recvProgress: func(n int64) {
			recvProgressTotal += n
		},
	})
	if send.err != nil || recv.err != nil {
		t.Fatalf("zero-byte resume: send=%v recv=%v", send.err, recv.err)
	}
	if recvProgressTotal != 0 {
		t.Fatalf("zero-byte resume transferred %d new bytes, want 0", recvProgressTotal)
	}
	if send.out.Digest != recv.out.Digest {
		t.Fatalf("digests differ after zero-byte resume: %s vs %s", send.out.Digest, recv.out.Digest)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("finalized file differs from source")
	}
	// Finalized: the journal is gone.
	if entries, _ := recvStore.List(); len(entries) != 0 {
		t.Fatalf("journal not removed after finalize: %#v", entries)
	}
}

// TestDriverCrashAfterResumeAuthBeforeManifest pins the sender boundary "after resume-auth
// success, before the resumed Manifest": the sender cancels the moment its preamble
// completes, so the manifest never goes out; the receiver's journal is untouched and a
// later attempt resumes normally.
func TestDriverCrashAfterResumeAuthBeforeManifest(t *testing.T) {
	senderStore := testSenderStore(t)
	outDir := t.TempDir()
	srcDir := t.TempDir()
	payload := make([]byte, 8<<20)
	for i := range payload {
		payload[i] = byte(i*23 + 7)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{srcPath}
	srec, j := seedInterruptedTransfer(t, senderStore, outDir, args)
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	committedBefore := before[0].CommittedBytes

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	crashCh := make(chan struct{})
	legCtx, legCancel := context.WithCancel(ctx)
	defer legCancel()
	sendCtx, sendCancel := context.WithCancel(legCtx)
	defer sendCancel()
	_ = crashCh
	// The sender's OnResume fires AFTER mutual auth completes and BEFORE the manifest is
	// built/sent: cancelling there deterministically crashes at that boundary.
	send, recv, _, _ := runResumeLeg(sendCtx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: &ResumeContext{
			TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint,
			Role: wire.RoleOfferer, ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		},
		recvResume: &ResumeContext{
			TransferID: j.TransferID, ManifestFingerprint: j.ManifestFingerprint,
			Role: wire.RoleJoiner, ResumeSecret: decodeJournalSecret(t, j.ResumeSecret),
		},
		sendCaps: resumeCaps(),
		recvCaps: resumeCaps(),
		onSendResume: func(r ResumeResult) {
			if r.Authenticated {
				sendCancel()
			}
		},
	})
	if send.err == nil || recv.err == nil {
		t.Fatalf("crash leg must fail: send=%v recv=%v", send.err, recv.err)
	}
	after, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 1 || after[0].CommittedBytes != committedBefore {
		t.Fatalf("journal moved before the resumed manifest: before=%d after=%#v", committedBefore, after)
	}

	// A later attempt resumes normally from the preserved state.
	send2, recv2, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: &ResumeContext{
			TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint,
			Role: wire.RoleOfferer, ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		},
		recvResume: &ResumeContext{
			TransferID: j.TransferID, ManifestFingerprint: j.ManifestFingerprint,
			Role: wire.RoleJoiner, ResumeSecret: decodeJournalSecret(t, j.ResumeSecret),
		},
		sendCaps: resumeCaps(),
		recvCaps: resumeCaps(),
	})
	if send2.err != nil || recv2.err != nil {
		t.Fatalf("resume after the crash boundary: send=%v recv=%v", send2.err, recv2.err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed file differs from source")
	}
}

// TestDriverCrashDuringResumedDataFlow pins a crash inside the RESUME leg (after
// resume-auth, mid-data): the journal advances only for verified blocks, and a THIRD
// fresh attempt re-authenticates and completes.
func TestDriverCrashDuringResumedDataFlow(t *testing.T) {
	senderStore := testSenderStore(t)
	outDir := t.TempDir()
	srcDir := t.TempDir()
	payload := make([]byte, 16<<20)
	for i := range payload {
		payload[i] = byte(i*29 + 11)
	}
	srcPath := filepath.Join(srcDir, "payload.bin")
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{srcPath}
	srec, j := seedInterruptedTransfer(t, senderStore, outDir, args)
	recvStore, err := OpenStore(outDir)
	if err != nil {
		t.Fatal(err)
	}
	before, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	committedBefore := before[0].CommittedBytes

	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	resumeCtx := func() *ResumeContext {
		return &ResumeContext{
			TransferID: srec.TransferID, ManifestFingerprint: srec.ManifestFingerprint,
			Role: wire.RoleOfferer, ResumeSecret: decodeRecordSecret(t, srec.ResumeSecret),
		}
	}
	recvResumeCtx := func() *ResumeContext {
		return &ResumeContext{
			TransferID: j.TransferID, ManifestFingerprint: j.ManifestFingerprint,
			Role: wire.RoleJoiner, ResumeSecret: decodeJournalSecret(t, j.ResumeSecret),
		}
	}

	// Resume leg 1: crash after the first resumed block commits.
	send1, recv1, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		interrupt:  true,
		sendResume: resumeCtx(),
		recvResume: recvResumeCtx(),
		sendCaps:   resumeCaps(),
		recvCaps:   resumeCaps(),
	})
	if send1.err == nil || recv1.err == nil {
		t.Fatalf("resume leg 1 must be interrupted: send=%v recv=%v", send1.err, recv1.err)
	}
	mid, err := recvStore.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(mid) != 1 || mid[0].CommittedBytes <= committedBefore || mid[0].CommittedBytes >= int64(len(payload)) {
		t.Fatalf("resume leg 1 checkpoint must advance strictly: before=%d after=%#v", committedBefore, mid)
	}

	// Resume leg 2: re-authenticate (fresh nonces) and complete.
	send2, recv2, _, _ := runResumeLeg(ctx, t, senderStore, outDir, args, resumeLegSpec{
		sendResume: resumeCtx(),
		recvResume: recvResumeCtx(),
		sendCaps:   resumeCaps(),
		recvCaps:   resumeCaps(),
	})
	if send2.err != nil || recv2.err != nil {
		t.Fatalf("resume leg 2: send=%v recv=%v", send2.err, recv2.err)
	}
	got, err := os.ReadFile(filepath.Join(outDir, "payload.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("resumed file differs from source")
	}
	if entries, _ := recvStore.List(); len(entries) != 0 {
		t.Fatalf("journal not removed after finalize: %#v", entries)
	}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
