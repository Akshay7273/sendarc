package transfer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"
	"github.com/sendbeam/cli/internal/rendezvous"
	"github.com/sendbeam/wire"
)

const (
	// durableTestID is the fixed 32-hex transfer id used across durable tests.
	durableTestID = "0123456789abcdef0123456789abcdef"
	// durableTestMime / durableTestMtime are the exact FileMeta values the loopback sender
	// reproduces, so journal fingerprints match between direct-drive and loopback phases.
	durableTestMime  = "application/octet-stream"
	durableTestMtime = 1_700_000_000_000
)

// durableTestData builds deterministic content.
func durableTestData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*29 + 7)
	}
	return data
}

// durableTestManifest builds a canonical manifest with real geometry and digests.
func durableTestManifest(t *testing.T, transferID string, blockSize int, contents map[string][]byte) wire.Manifest {
	t.Helper()
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	files := make([]wire.FileEntry, len(names))
	var total int64
	for i, name := range names {
		data := contents[name]
		blocks := 0
		if len(data) > 0 {
			blocks = (len(data)-1)/blockSize + 1
		}
		sum := sha256.Sum256(data)
		files[i] = wire.FileEntry{
			Idx: i, Name: name, Size: int64(len(data)), Mime: durableTestMime,
			LastModified: durableTestMtime, BlockSize: blockSize, Blocks: blocks,
			FileDigest: hex.EncodeToString(sum[:]),
		}
		total += int64(len(data))
	}
	m := wire.NewManifest(files, total)
	if transferID != "" {
		m.TransferID = transferID
	}
	return *m
}

// writeDurableBlocks writes whole blocks through a sink exactly as the wire layer does,
// then closes the sink.
func writeDurableBlocks(t *testing.T, sink wire.Sink, blockSize int, data []byte) {
	t.Helper()
	for off := 0; off < len(data); off += blockSize {
		end := off + blockSize
		if end > len(data) {
			end = len(data)
		}
		if err := sink.Write(int64(off), data[off:end]); err != nil {
			t.Fatalf("sink.Write(%d): %v", off, err)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("sink.Close: %v", err)
	}
}

// journalOnDisk reloads the journal for one transfer from the store.
func journalOnDisk(t *testing.T, dest *DurableDestination) wire.DurableJournal {
	t.Helper()
	j, ok, err := dest.Store().LoadJournal(durableTestID)
	if err != nil {
		t.Fatalf("reload journal: %v", err)
	}
	if !ok {
		t.Fatal("journal missing from disk")
	}
	return j
}

// partialSize returns the on-disk size of one file's .part.
func partialSize(t *testing.T, dest *DurableDestination, name string) int64 {
	t.Helper()
	info, err := os.Stat(dest.Store().PartialPath(durableTestID, name))
	if err != nil {
		t.Fatalf("stat partial %s: %v", name, err)
	}
	return info.Size()
}

// durableLoopbackMaster is the fixed master key for the in-package loopback (mirrors the
// wire package's loopback harness).
func durableLoopbackMaster() []byte {
	m := make([]byte, 32)
	for i := range m {
		m[i] = 3
	}
	return m
}

// runDurableLoopback wires a resumable Sender to a Receiver over the durable destination.
// The resume seed is applied through OnManifestSet exactly as the CLI driver does: the
// authenticated manifest binds the journal, then per-file high-water marks and digest
// prefixes are rebuilt from the persisted partials.
func runDurableLoopback(t *testing.T, dest *DurableDestination, blockSize int, contents map[string][]byte) (sendErr, recvErr error) {
	t.Helper()
	keys, err := wire.DeriveTransferKeys(durableLoopbackMaster())
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(contents))
	for name := range contents {
		names = append(names, name)
	}
	sort.Strings(names)
	sources := make([]wire.FileSource, len(names))
	for i, name := range names {
		sources[i] = wire.BytesSource(contents[name], wire.FileMeta{
			Name: name, Size: int64(len(contents[name])), Mime: durableTestMime,
			LastModified: durableTestMtime,
		}, 0)
	}
	s2r := make(chan []byte, 4096)
	r2s := make(chan []byte, 4096)
	cp := func(f []byte) []byte { return append([]byte(nil), f...) }
	sender := wire.NewSender(wire.SenderOptions{
		Files: sources, Send: func(f []byte) error { s2r <- cp(f); return nil },
		SendDir: keys.O2J, RecvDir: keys.J2O,
		BlockSize: blockSize, FrameSize: 4096, Window: 4,
		TransferID: durableTestID,
	})
	var sharedResume wire.ReceiverResume
	receiver := wire.NewReceiver(wire.ReceiverOptions{
		Send:    func(f []byte) error { r2s <- cp(f); return nil },
		SendDir: keys.J2O, RecvDir: keys.O2J,
		Destination: dest, Resume: &sharedResume,
		OnManifestSet: func(manifest wire.Manifest) error {
			resume, err := dest.ResumeStateFor(manifest)
			if err != nil {
				return err
			}
			if resume != nil {
				sharedResume = *resume
			}
			return nil
		},
	})
	go func() {
		for f := range s2r {
			receiver.Handle(f)
		}
	}()
	go func() {
		for f := range r2s {
			sender.Handle(f)
		}
	}()
	sendDone := make(chan error, 1)
	go func() {
		_, e := sender.Run(context.Background())
		sendDone <- e
	}()
	_, recvErr = receiver.Wait(context.Background())
	sendErr = <-sendDone
	close(s2r)
	close(r2s)
	return sendErr, recvErr
}

// TestDurableFreshTransferFinalizes pins the happy path: verified blocks land in .part
// files, the journal tracks them, and after whole-transfer verification the finals appear,
// the journal is removed, and no .part survives.
func TestDurableFreshTransferFinalizes(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	contents := map[string][]byte{
		"a.txt":        durableTestData(2048),
		"nested/b.bin": durableTestData(1024),
		"empty.txt":    {}, // zero-byte file: opened, closed, finalized with no writes
	}
	manifest := durableTestManifest(t, durableTestID, blockSize, contents)
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	for _, file := range manifest.Files {
		sink, err := dest.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		writeDurableBlocks(t, sink, blockSize, contents[file.Name])
	}
	if err := dest.Close(); err != nil {
		t.Fatal(err)
	}
	for name, want := range contents {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("final %s: %v", name, err)
		}
		if string(got) != string(want) {
			t.Fatalf("final %s differs", name)
		}
	}
	// No .part files, no journal, no partial tree remain after finalize.
	var parts []string
	_ = filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err == nil && strings.HasSuffix(entry.Name(), durablePartSuffix) {
			parts = append(parts, path)
		}
		return nil
	})
	if len(parts) != 0 {
		t.Fatalf("leftover .part files: %v", parts)
	}
	if _, ok, _ := dest.Store().LoadJournal(durableTestID); ok {
		t.Fatal("journal survived finalize")
	}
}

// TestDurableCheckpointNeverAheadOfDurableData pins the ADR ordering contract at the
// storage layer: after every block the on-disk journal's checkpoint exactly equals the
// durable partial length, so a crash at any point can never claim un-durable bytes.
func TestDurableCheckpointNeverAheadOfDurableData(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(4 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	for block := 0; block < 4; block++ {
		chunk := content[block*blockSize : (block+1)*blockSize]
		if err := sink.Write(int64(block*blockSize), chunk); err != nil {
			t.Fatal(err)
		}
		j := journalOnDisk(t, dest)
		if got := j.Files[0].CommittedBlocks; got != block+1 {
			t.Fatalf("after block %d committedBlocks = %d, want %d", block, got, block+1)
		}
		if got := partialSize(t, dest, "f.bin"); got != int64((block+1)*blockSize) {
			t.Fatalf("after block %d partial size = %d, want %d (checkpoint must never exceed durable data)",
				block, got, (block+1)*blockSize)
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestDurableFailureBeforeDurabilityBarrier pins crash point "after data write, before
// durability barrier": the fsync fails, so the checkpoint must NOT advance past the last
// durable block, and a resume re-transfers the unclaimed tail safely.
func TestDurableFailureBeforeDurabilityBarrier(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(4 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})

	// Fail the durability barrier on the second block's fsync.
	fsyncs := 0
	dest.hooks.syncFile = func(f *os.File) error {
		fsyncs++
		if fsyncs == 2 {
			return errors.New("fsync failed: EIO")
		}
		return f.Sync()
	}
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, content[:blockSize]); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(int64(blockSize), content[blockSize:2*blockSize]); err == nil {
		t.Fatal("second block must fail at the durability barrier")
	}
	if err := dest.Abort("fsync failure"); err != nil {
		t.Fatal(err)
	}

	// The checkpoint claims exactly one block (the durable one); the second block's bytes
	// reached the page cache but were never made durable and are unclaimed.
	j := journalOnDisk(t, dest)
	if j.Files[0].CommittedBlocks != 1 {
		t.Fatalf("checkpoint advanced past the durability barrier: %d blocks", j.Files[0].CommittedBlocks)
	}
	// Nothing was deleted: the journal and partial survive for resume.
	if _, ok, _ := dest.Store().LoadJournal(durableTestID); !ok {
		t.Fatal("journal deleted on failure")
	}

	// A fresh destination resumes from the durable checkpoint and completes.
	resumed, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	sendErr, recvErr := runDurableLoopback(t, resumed, blockSize, map[string][]byte{"f.bin": content})
	if sendErr != nil || recvErr != nil {
		t.Fatalf("resume after barrier failure: send=%v receive=%v", sendErr, recvErr)
	}
	got, err := os.ReadFile(filepath.Join(dir, "f.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("resumed file differs from source")
	}
}

// TestDurableFailureAfterDurableDataBeforeJournalCommit pins crash point "after durable
// data, before journal update": the block is fsynced but its commit fails, so the journal
// stays at the previous checkpoint while the partial holds an unclaimed tail; resume
// truncates to the checkpoint and re-transfers safely.
func TestDurableFailureAfterDurableDataBeforeJournalCommit(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(4 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})

	// Fail the journal commit on the second block.
	commits := 0
	dest.hooks.writeJournal = func(path string, j wire.DurableJournal) error {
		commits++
		if commits == 2 {
			return errors.New("journal write failed: EIO")
		}
		return wire.WriteJournalAtomic(path, j)
	}
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, content[:blockSize]); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(int64(blockSize), content[blockSize:2*blockSize]); err == nil {
		t.Fatal("second block must fail at the journal commit")
	}
	if err := dest.Abort("journal commit failure"); err != nil {
		t.Fatal(err)
	}

	j := journalOnDisk(t, dest)
	if j.Files[0].CommittedBlocks != 1 {
		t.Fatalf("journal advanced despite failed commit: %d blocks", j.Files[0].CommittedBlocks)
	}
	// The data is durable but unclaimed: the partial holds two blocks, the journal one.
	if size := partialSize(t, dest, "f.bin"); size != 2*int64(blockSize) {
		t.Fatalf("partial size = %d, want %d (durable but unclaimed tail)", size, 2*int64(blockSize))
	}

	// Resume truncates the partial to the authoritative checkpoint and re-transfers.
	resumed, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	sendErr, recvErr := runDurableLoopback(t, resumed, blockSize, map[string][]byte{"f.bin": content})
	if sendErr != nil || recvErr != nil {
		t.Fatalf("resume after failed commit: send=%v receive=%v", sendErr, recvErr)
	}
	got, err := os.ReadFile(filepath.Join(dir, "f.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("resumed file differs from source")
	}
}

// TestDurableJournalCommitFailureFailsClosed pins that a persistent journal-write failure
// fails the transfer closed at the first commit: no journal exists to claim anything, the
// partial holds unclaimed bytes, and the store surfaces the state as an orphan.
func TestDurableJournalCommitFailureFailsClosed(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})
	dest.hooks.writeJournal = func(string, wire.DurableJournal) error {
		return errors.New("journal write failed: EIO")
	}
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, content); err == nil {
		t.Fatal("block write must fail when the journal commit fails")
	}
	if err := dest.Abort("commit failure"); err != nil {
		t.Fatal(err)
	}
	// The journal was created at Prepare but never advanced: nothing is claimed, the
	// partial holds unclaimed bytes, and the transfer failed closed without deletions.
	j := journalOnDisk(t, dest)
	if j.Files[0].CommittedBlocks != 0 {
		t.Fatalf("journal advanced despite every commit failing: %d blocks", j.Files[0].CommittedBlocks)
	}
	entries, err := dest.Store().List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].JournalOK || entries[0].CommittedBytes != 0 {
		t.Fatalf("store must surface the un-advanced journal, got %+v", entries)
	}
}

// TestDurableResumeFromCheckpointEndToEnd pins the full resume path: a checkpoint built by
// one process is adopted by a fresh destination, the wire layer streams only the missing
// blocks (seeded digest re-hashed from the persisted prefix), and the transfer completes
// byte-identically with clean finalize.
func TestDurableResumeFromCheckpointEndToEnd(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(5 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})

	// "Crash" after the first two blocks: write them, close the sink, and abandon the
	// destination without finalizing.
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, content[:2*blockSize])
	j := journalOnDisk(t, dest)
	if j.Files[0].CommittedBlocks != 2 {
		t.Fatalf("seed checkpoint = %d blocks, want 2", j.Files[0].CommittedBlocks)
	}

	// Fresh process: resume from the checkpoint.
	resumed, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	sendErr, recvErr := runDurableLoopback(t, resumed, blockSize, map[string][]byte{"f.bin": content})
	if sendErr != nil || recvErr != nil {
		t.Fatalf("resume: send=%v receive=%v", sendErr, recvErr)
	}
	got, err := os.ReadFile(filepath.Join(dir, "f.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("resumed file differs from source")
	}
	if _, ok, _ := resumed.Store().LoadJournal(durableTestID); ok {
		t.Fatal("journal survived finalize after resume")
	}
}

// TestDurableFullyCommittedResumeCompletesWithoutData pins the "all files complete, final
// Done lost" case: the journal is fully committed but never finalized, so a resume must
// adopt the held bytes (HaveBlocks == Blocks for every file) and finish without
// re-streaming data.
func TestDurableFullyCommittedResumeCompletesWithoutData(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(3 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, content) // every block committed, never finalized
	if j := journalOnDisk(t, dest); j.Files[0].CommittedBlocks != 3 {
		t.Fatalf("committed = %d, want 3", j.Files[0].CommittedBlocks)
	}

	resumed, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	sendErr, recvErr := runDurableLoopback(t, resumed, blockSize, map[string][]byte{"f.bin": content})
	if sendErr != nil || recvErr != nil {
		t.Fatalf("adopt-and-finalize: send=%v receive=%v", sendErr, recvErr)
	}
	got, err := os.ReadFile(filepath.Join(dir, "f.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("adopted file differs from source")
	}
}

// TestDurableMissingOrTruncatedPartialFailsClosed pins fail-closed handling of partial
// data that cannot back the journal's claims: resume is refused, nothing is deleted, and
// the state stays inspectable and discardable.
func TestDurableMissingOrTruncatedPartialFailsClosed(t *testing.T) {
	blockSize := 1024
	content := durableTestData(2 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, dir string)
	}{
		{"missing partial", func(t *testing.T, dir string) {
			part := filepath.Join(dir, ".sendbeam", "partials", durableTestID, "f.bin.part")
			if err := os.Remove(part); err != nil {
				t.Fatal(err)
			}
		}},
		{"truncated partial", func(t *testing.T, dir string) {
			part := filepath.Join(dir, ".sendbeam", "partials", durableTestID, "f.bin.part")
			if err := os.Truncate(part, int64(blockSize)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dest, err := NewDurableDestination(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := dest.Prepare(manifest); err != nil {
				t.Fatal(err)
			}
			sink, err := dest.Open(manifest.Files[0])
			if err != nil {
				t.Fatal(err)
			}
			writeDurableBlocks(t, sink, blockSize, content)
			tc.mutate(t, dir)

			resumed, err := NewDurableDestination(dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := resumed.Prepare(manifest); err != nil {
				t.Fatalf("Prepare with the matching journal must succeed: %v", err)
			}
			if _, err := resumed.ResumeStateFor(manifest); err == nil {
				t.Fatal("resume must fail closed when partial data cannot back the journal")
			}
			// Nothing was deleted, and the store still inspects/discards it.
			if _, ok, _ := resumed.Store().LoadJournal(durableTestID); !ok {
				t.Fatal("journal was deleted on a storage error")
			}
			ins, err := resumed.Store().Inspect(durableTestID)
			if err != nil {
				t.Fatalf("inspect after storage error: %v", err)
			}
			if ins.Resumable || len(ins.Problems) == 0 {
				t.Fatalf("inspect must report the inconsistency, got %+v", ins)
			}
			if err := resumed.Store().Discard(durableTestID); err != nil {
				t.Fatalf("discard after storage error: %v", err)
			}
		})
	}
}

// TestDurableCorruptJournalFailsClosed pins that a corrupt, torn, or tampered journal is
// rejected closed at load: the transfer fails, the journal is never deleted, and list
// surfaces it as unreadable while discard removes it.
func TestDurableCorruptJournalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	blockSize := 1024
	content := durableTestData(blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})

	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, content)

	// Corrupt the journal: flip a byte inside the checksum so decode fails closed.
	journalPath := dest.Store().JournalPath(durableTestID)
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	idx := strings.LastIndex(string(data), `"checksum":"`)
	if idx < 0 {
		t.Fatal("checksum not found")
	}
	if data[idx+len(`"checksum":"`)] == '0' {
		data[idx+len(`"checksum":"`)] = '1'
	} else {
		data[idx+len(`"checksum":"`)] = '0'
	}
	if err := os.WriteFile(journalPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	// A new destination for the same manifest must fail closed at Prepare.
	resumed, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := resumed.Prepare(manifest); err == nil {
		t.Fatal("corrupt journal must fail closed at Prepare")
	}
	if _, ok, _ := resumed.Store().LoadJournal(durableTestID); !ok {
		t.Fatal("corrupt journal was deleted")
	}
	entries, err := resumed.Store().List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].JournalOK || entries[0].Err == "" {
		t.Fatalf("list must surface the unreadable journal, got %+v", entries)
	}
	if err := resumed.Store().Discard(durableTestID); err != nil {
		t.Fatal(err)
	}
	if entries, _ := resumed.Store().List(); len(entries) != 0 {
		t.Fatalf("discard did not remove the corrupt journal: %+v", entries)
	}
}

// TestDurableMismatchedJournalFailsClosed pins that a journal whose fingerprint does not
// match the authenticated manifest (transfer id reused for a different file set) is
// rejected closed, and that a different transfer id starts fresh without touching the old
// journal.
func TestDurableMismatchedJournalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	blockSize := 1024
	first := map[string][]byte{"a.txt": durableTestData(2 * blockSize)}
	other := map[string][]byte{"b.bin": durableTestData(3 * blockSize)}

	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	firstManifest := durableTestManifest(t, durableTestID, blockSize, first)
	if err := dest.Prepare(firstManifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(firstManifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, first["a.txt"])

	// Same transfer id, different file set: the fingerprint check must fail closed.
	otherDest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := otherDest.Prepare(durableTestManifest(t, durableTestID, blockSize, other)); err == nil {
		t.Fatal("mismatched journal must fail closed at Prepare")
	}
	// The old journal and its partials survive untouched.
	if j := journalOnDisk(t, dest); j.Files[0].CommittedBlocks != 2 {
		t.Fatalf("original journal corrupted: %d blocks", j.Files[0].CommittedBlocks)
	}

	// A different transfer id starts a fresh journal and leaves the old one alone.
	freshID := "ffffffffffffffffffffffffffffffff"
	fresh, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := fresh.Prepare(durableTestManifest(t, freshID, blockSize, other)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := fresh.Store().LoadJournal(freshID); !ok {
		t.Fatal("fresh journal not created")
	}
	if _, ok, _ := fresh.Store().LoadJournal(durableTestID); !ok {
		t.Fatal("old journal was removed")
	}
}

// TestDurableFinalizeRefusesOverwrite pins the no-overwrite guarantee at finalize: a
// destination that appeared during the transfer is never clobbered; finalize fails closed
// and the partials + journal are kept.
func TestDurableFinalizeRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	blockSize := 1024
	content := durableTestData(2 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})

	// A file appears at the final path mid-transfer (the user or another process).
	finalPath := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(finalPath, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, content)
	if err := dest.Close(); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("finalize must refuse to overwrite, got %v", err)
	}
	got, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep me" {
		t.Fatalf("existing destination was modified: %q", got)
	}
	// The resumable state is intact: journal + partial remain.
	if _, ok, _ := dest.Store().LoadJournal(durableTestID); !ok {
		t.Fatal("journal deleted after refused finalize")
	}
	if _, err := os.Stat(dest.Store().PartialPath(durableTestID, "f.bin")); err != nil {
		t.Fatalf("partial deleted after refused finalize: %v", err)
	}
}

// TestDurablePathAndSymlinkSafety pins that hostile manifest paths, .sendbeam collisions,
// and symlinked destination or partial components fail closed exactly where the old sink
// refused them.
func TestDurablePathAndSymlinkSafety(t *testing.T) {
	blockSize := 1024
	content := durableTestData(blockSize)

	t.Run("traversal rejected", func(t *testing.T) {
		dir := t.TempDir()
		dest, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"../escape.txt": content})
		if err := dest.Prepare(manifest); err == nil {
			t.Fatal("traversal path must be rejected")
		}
	})

	t.Run("sendbeam collision rejected", func(t *testing.T) {
		dir := t.TempDir()
		dest, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{".sendbeam", ".sendbeam/evil.txt"} {
			manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{name: content})
			if err := dest.Prepare(manifest); err == nil {
				t.Fatalf("manifest path %q must be rejected at Prepare", name)
			}
		}
	})

	t.Run("symlinked final component rejected", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		dest, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"linked/escape.txt": content})
		if err := dest.Prepare(manifest); err != nil {
			t.Fatal(err)
		}
		if _, err := dest.Open(manifest.Files[0]); err == nil {
			t.Fatal("symlinked destination component must be rejected")
		}
	})

	t.Run("symlinked partial component rejected", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		partialBase := filepath.Join(dir, ".sendbeam", "partials", durableTestID)
		if err := os.MkdirAll(partialBase, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(partialBase, "linked")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		dest, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"linked/escape.txt": content})
		if err := dest.Prepare(manifest); err != nil {
			t.Fatal(err)
		}
		if _, err := dest.Open(manifest.Files[0]); err == nil {
			t.Fatal("symlinked partial component must be rejected")
		}
	})

	t.Run("symlinked partial file rejected on resume", func(t *testing.T) {
		dir := t.TempDir()
		outside := t.TempDir()
		target := filepath.Join(outside, "victim.bin")
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
		manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})

		seed, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := seed.Prepare(manifest); err != nil {
			t.Fatal(err)
		}
		sink, err := seed.Open(manifest.Files[0])
		if err != nil {
			t.Fatal(err)
		}
		writeDurableBlocks(t, sink, blockSize, content)

		// Replace the partial with a symlink to an outside file: resume must refuse and
		// must never truncate or write through the symlink.
		part := seed.Store().PartialPath(durableTestID, "f.bin")
		if err := os.Remove(part); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, part); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		resumed, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := resumed.Prepare(manifest); err != nil {
			t.Fatal(err)
		}
		if _, err := resumed.ResumeStateFor(manifest); err == nil {
			t.Fatal("resume must refuse a symlinked partial")
		}
		if _, err := resumed.Open(manifest.Files[0]); err == nil {
			t.Fatal("Open must refuse a symlinked partial")
		}
		got, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(content) {
			t.Fatal("symlinked partial target was modified")
		}
	})
}

// TestDurableBudgetEnforced pins the disk-budget contract: checkpoints are refused with
// FailQuota once partial data + journal exceed the budget, the journal stops advancing,
// and nothing is deleted.
func TestDurableBudgetEnforced(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(3 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	j, ok, err := dest.Store().LoadJournal(durableTestID)
	if err != nil || !ok {
		t.Fatalf("load fresh journal: %v ok=%v", err, ok)
	}
	encoded, err := wire.EncodeJournal(j)
	if err != nil {
		t.Fatal(err)
	}
	// Budget fits exactly one block of partial data plus the journal.
	dest.Store().SetBudget(int64(blockSize) + int64(len(encoded)))

	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(0, content[:blockSize]); err != nil {
		t.Fatalf("first block must fit the budget: %v", err)
	}
	secondErr := sink.Write(int64(blockSize), content[blockSize:2*blockSize])
	if secondErr == nil {
		t.Fatal("second block must exceed the budget")
	}
	var te *wire.TransferError
	if !errors.As(secondErr, &te) || te.Reason != wire.FailQuota {
		t.Fatalf("budget breach must surface FailQuota, got %v", secondErr)
	}
	if j := journalOnDisk(t, dest); j.Files[0].CommittedBlocks != 1 {
		t.Fatalf("journal advanced past the budget: %d blocks", j.Files[0].CommittedBlocks)
	}
	if err := dest.Abort("budget"); err != nil {
		t.Fatal(err)
	}
	// The resumable state survives the quota failure.
	if _, ok, _ := dest.Store().LoadJournal(durableTestID); !ok {
		t.Fatal("journal deleted after quota failure")
	}
}

// TestDurableAbortKeepsResumableState pins the PR02 abort contract: a cancelled or failed
// transfer keeps its journal and .part files (the only resumable data) and never leaves a
// final-looking file in the out directory.
func TestDurableAbortKeepsResumableState(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(3 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, content[:2*blockSize])
	if err := dest.Abort("peer canceled"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := dest.Store().LoadJournal(durableTestID); !ok {
		t.Fatal("abort deleted the journal")
	}
	if _, err := os.Stat(dest.Store().PartialPath(durableTestID, "f.bin")); err != nil {
		t.Fatalf("abort deleted the partial: %v", err)
	}
	// No final-looking file may exist in the out directory.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".") {
			t.Fatalf("aborted transfer left a final-looking file: %s", entry.Name())
		}
	}
	// Discard is the explicit cleanup and is idempotent.
	if err := dest.Store().Discard(durableTestID); err != nil {
		t.Fatal(err)
	}
	if err := dest.Store().Discard(durableTestID); err != nil {
		t.Fatalf("repeat discard must be safe: %v", err)
	}
}

// TestDurableStoreListInspectDiscard pins the management surface: valid journals, unreadable
// journals, and orphaned partial trees are all listed; inspect validates; discard is
// bounded to one transfer and never touches the rest.
func TestDurableStoreListInspectDiscard(t *testing.T) {
	dir := t.TempDir()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024

	// Transfer A: journal + committed partials.
	aContent := durableTestData(2 * blockSize)
	a, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	aManifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"a.txt": aContent})
	if err := a.Prepare(aManifest); err != nil {
		t.Fatal(err)
	}
	sink, err := a.Open(aManifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, aContent)

	// Transfer B: journal + committed partials under a second id.
	bID := "11111111111111111111111111111111"
	bContent := durableTestData(blockSize)
	b, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	bManifest := durableTestManifest(t, bID, blockSize, map[string][]byte{"b.bin": bContent})
	if err := b.Prepare(bManifest); err != nil {
		t.Fatal(err)
	}
	sink, err = b.Open(bManifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, bContent)

	// Corrupt A's journal so list must surface it without deleting it.
	journalPath := store.JournalPath(durableTestID)
	data, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(journalPath, data[:len(data)-2], 0o600); err != nil {
		t.Fatal(err)
	}

	// Orphaned partial tree: no journal.
	orphanID := "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	if err := os.MkdirAll(store.PartialDir(orphanID), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.PartialDir(orphanID), "lost.part"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("list = %d entries, want 3 (%+v)", len(entries), entries)
	}
	byID := map[string]DurableEntry{}
	for _, e := range entries {
		byID[e.TransferID] = e
	}
	if e := byID[durableTestID]; e.JournalOK {
		t.Fatalf("corrupt journal listed as valid: %+v", e)
	}
	if e := byID[bID]; !e.JournalOK || e.CommittedBytes != int64(blockSize) {
		t.Fatalf("transfer B listed wrong: %+v", e)
	}
	if e := byID[orphanID]; !e.Orphaned {
		t.Fatalf("orphan not flagged: %+v", e)
	}

	// Inspect the healthy journal.
	ins, err := store.Inspect(bID)
	if err != nil {
		t.Fatal(err)
	}
	if !ins.Resumable || ins.Committed != int64(blockSize) || ins.FilesChecked != 1 {
		t.Fatalf("inspect B: %+v", ins)
	}

	// Discard B: bounded — A's corrupt journal, its partials, and the orphan survive.
	if err := store.Discard(bID); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := store.LoadJournal(bID); ok {
		t.Fatal("B journal survived discard")
	}
	if _, ok, _ := store.LoadJournal(durableTestID); !ok {
		t.Fatal("discard touched A's journal")
	}
	if _, err := os.Stat(store.PartialDir(orphanID)); err != nil {
		t.Fatal("discard touched the orphan")
	}
	// Discarding an already-absent id is a safe no-op.
	if err := store.Discard(bID); err != nil {
		t.Fatalf("repeat discard: %v", err)
	}

	// DiscardAll removes everything, including the corrupt journal and the orphan.
	if err := store.DiscardAll(); err != nil {
		t.Fatal(err)
	}
	entries, err = store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("store not empty after DiscardAll: %+v", entries)
	}
}

// TestDurableNoTransferIDNonResumable pins the legacy-sender path: a manifest without a
// transfer id gets no journal, still finalizes through .part files, and its temp partials
// are removed on both finalize and abort.
func TestDurableNoTransferIDNonResumable(t *testing.T) {
	t.Run("finalize cleans temp partials", func(t *testing.T) {
		dir := t.TempDir()
		dest, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		blockSize := 1024
		content := durableTestData(2 * blockSize)
		manifest := durableTestManifest(t, "", blockSize, map[string][]byte{"f.bin": content})
		if err := dest.Prepare(manifest); err != nil {
			t.Fatal(err)
		}
		sink, err := dest.Open(manifest.Files[0])
		if err != nil {
			t.Fatal(err)
		}
		writeDurableBlocks(t, sink, blockSize, content)
		if err := dest.Close(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(dir, "f.bin"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(content) {
			t.Fatal("final differs")
		}
		// No journal and no temp partial tree survive.
		partials, err := os.ReadDir(filepath.Join(dir, ".sendbeam", "partials"))
		if err != nil {
			t.Fatal(err)
		}
		if len(partials) != 0 {
			t.Fatalf("temp partials survived finalize: %v", partials)
		}
		if entries, _ := dest.Store().List(); len(entries) != 0 {
			t.Fatalf("no-id transfer listed: %+v", entries)
		}
	})

	t.Run("abort removes temp partials", func(t *testing.T) {
		dir := t.TempDir()
		dest, err := NewDurableDestination(dir)
		if err != nil {
			t.Fatal(err)
		}
		blockSize := 1024
		content := durableTestData(2 * blockSize)
		manifest := durableTestManifest(t, "", blockSize, map[string][]byte{"f.bin": content})
		if err := dest.Prepare(manifest); err != nil {
			t.Fatal(err)
		}
		sink, err := dest.Open(manifest.Files[0])
		if err != nil {
			t.Fatal(err)
		}
		writeDurableBlocks(t, sink, blockSize, content[:blockSize])
		if err := dest.Abort("canceled"); err != nil {
			t.Fatal(err)
		}
		partials, err := os.ReadDir(filepath.Join(dir, ".sendbeam", "partials"))
		if err != nil {
			t.Fatal(err)
		}
		if len(partials) != 0 {
			t.Fatalf("temp partials survived abort: %v", partials)
		}
		if _, err := os.Stat(filepath.Join(dir, "f.bin")); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("aborted no-id transfer left a final file")
		}
	})
}

// TestDriverDurableReceiveEndToEnd runs the full driver pair through the in-memory relay:
// the receiver journals mid-transfer and the store is clean afterwards (finals only).
func TestDriverDurableReceiveEndToEnd(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(3*1024*1024 + 17)
	meta := wire.FileMeta{Name: "durable-e2e.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type result struct {
		out *Outcome
		err error
	}
	done := make(chan result, 2)
	go func() {
		out, err := Run(ctx, hub.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		})
		done <- result{out, err}
	}()
	go func() {
		out, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
		})
		done <- result{out, err}
	}()

	a, b := <-done, <-done
	if a.err != nil || b.err != nil {
		t.Fatalf("durable e2e results: %v / %v", a.err, b.err)
	}
	var recv *Outcome
	if a.out.Path != "" {
		recv = a.out
	} else {
		recv = b.out
	}
	got, err := os.ReadFile(recv.Path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("durable e2e output differs from source")
	}
	// The store is clean after finalize: no journals, no partials.
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("store not clean after finalize: %+v", entries)
	}
}

// TestDriverAbortKeepsResumableState pins the driver-level abort: cancelling the receiver
// mid-transfer keeps a valid journal and partials, and no final file appears.
func TestDriverAbortKeepsResumableState(t *testing.T) {
	hub := newRelay()
	payload := faultPayload(4 * 1024 * 1024)
	meta := wire.FileMeta{Name: "abort-resume.bin", Size: int64(len(payload)), Mime: "application/octet-stream"}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var mu sync.Mutex
	var controls Controls
	cancelOnce := sync.Once{}
	done := make(chan error, 2)
	go func() {
		_, err := Run(ctx, hub.off, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleOfferer, Words: "alpha-bravo"},
			Source:     wire.BytesSource(payload, meta, 64*1024),
			ICEServers: []webrtc.ICEServer{},
		})
		done <- err
	}()
	go func() {
		_, err := Run(ctx, hub.join, Spec{
			Session:    rendezvous.Options{Role: rendezvous.RoleJoiner, Code: "7-alpha-bravo"},
			DestDir:    dir,
			ICEServers: []webrtc.ICEServer{},
			OnControls: func(c Controls) {
				mu.Lock()
				controls = c
				mu.Unlock()
			},
			OnProgress: func(acknowledged int64) {
				mu.Lock()
				c := controls
				mu.Unlock()
				if acknowledged >= 2*1024*1024 {
					cancelOnce.Do(func() { _ = c.Cancel("test abort") })
				}
			},
		})
		done <- err
	}()

	for i := 0; i < 2; i++ {
		if err := <-done; err == nil {
			t.Fatal("expected the aborted transfer to fail")
		}
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := store.List()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !entries[0].JournalOK {
		t.Fatalf("expected one valid journal after abort, got %+v", entries)
	}
	entry := entries[0]
	if entry.CommittedBytes < 1024*1024 {
		t.Fatalf("journal checkpoint too small after abort: %d", entry.CommittedBytes)
	}
	part := store.PartialPath(entry.TransferID, "abort-resume.bin")
	info, err := os.Stat(part)
	if err != nil {
		t.Fatalf("partial missing after abort: %v", err)
	}
	if info.Size() < entry.CommittedBytes {
		t.Fatalf("partial (%d) shorter than checkpoint (%d)", info.Size(), entry.CommittedBytes)
	}
	// No final file may exist in the out directory.
	if _, err := os.Stat(filepath.Join(dir, "abort-resume.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("aborted transfer left a final file")
	}
}

// TestDurableJournalIsLocalStateNotWireMaterial pins that nothing secret ever reaches the
// journal: the master key, directional keys, and counters are absent from the encoded form
// of every journal produced by the durable destination.
func TestDurableJournalIsLocalStateNotWireMaterial(t *testing.T) {
	dir := t.TempDir()
	dest, err := NewDurableDestination(dir)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := 1024
	content := durableTestData(2 * blockSize)
	manifest := durableTestManifest(t, durableTestID, blockSize, map[string][]byte{"f.bin": content})
	if err := dest.Prepare(manifest); err != nil {
		t.Fatal(err)
	}
	sink, err := dest.Open(manifest.Files[0])
	if err != nil {
		t.Fatal(err)
	}
	writeDurableBlocks(t, sink, blockSize, content)

	data, err := os.ReadFile(dest.Store().JournalPath(durableTestID))
	if err != nil {
		t.Fatal(err)
	}
	master := durableLoopbackMaster()
	keys, err := wire.DeriveTransferKeys(master)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{master, keys.O2J.Key, keys.J2O.Key} {
		if len(secret) > 0 && strings.Contains(string(data), string(secret)) {
			t.Fatalf("journal contains raw key material")
		}
	}
}
