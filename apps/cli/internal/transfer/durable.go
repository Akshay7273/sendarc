package transfer

// CLI durable receive storage (V13-PR02).
//
// Layout under the receive out directory:
//
//	<out>/.sendbeam/
//	  <transferId>.json                 # wire.DurableJournal, mode 0600, atomic replace
//	  partials/<transferId>/<rel>.part  # verified partial data mirroring manifest paths
//	  partials/tmp-<random>/<rel>.part  # non-resumable partials (manifest had no transfer id)
//
// The journal never persists raw session keys, directional traffic keys, or live AEAD
// counters (ADR 0004 §5): the only secret-adjacent field is the opaque resumeSecret
// envelope, which PR02 never fills (that is PR07).
//
// Ordering contract (ADR 0004 §1): a block is acknowledged only after it is verified
// (the wire layer), written to the .part file, made durable (fsync), and its checkpoint
// atomically advanced in the journal. A crash at any earlier point leaves the previous
// checkpoint authoritative; the journal never advances ahead of durable data. Partial
// data is never mistaken for a final file: finals appear only after whole-transfer
// verification, promoted atomically (no-overwrite), after which the journal is removed.
//
// Fail-closed rules (ADR 0004 §3/§8): a journal that fails decode, validation, checksum,
// fingerprint, or destination-identity checks is rejected — never guessed, never deleted
// automatically. Partial data that is missing or shorter than the checkpoint claims is a
// storage error surfaced to the user; nothing resumable is ever deleted silently. Only
// the explicit discard command removes journals and their partial trees, idempotently.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sendbeam/wire"
)

// errSinkClosed is returned when a block is written after the destination has been
// closed or aborted. The engine never does this, so it only guards against misuse or a
// late concurrent abort.
var errSinkClosed = errors.New("transfer: write after sink closed")

const (
	// durableDirName is the hidden storage directory created inside the receive out dir.
	durableDirName = ".sendbeam"
	// durablePartialsDir holds every transfer's partial trees.
	durablePartialsDir = "partials"
	// durablePartSuffix marks partial data so it can never be mistaken for a final file.
	durablePartSuffix = ".part"
	// durableTempPrefix names the non-resumable partial trees of transfers whose manifest
	// carried no transfer id (legacy senders).
	durableTempPrefix = "tmp-"
)

// DurableStore is the .sendbeam storage area under one receive out directory. It owns the
// on-disk layout, journal load/save, listing, and the explicit discard operation.
type DurableStore struct {
	// outRoot is the resolved absolute out directory; root is <outRoot>/.sendbeam.
	outRoot     string
	root        string
	partialRoot string
	// budget bounds the total partial data + journal bytes a receive may checkpoint;
	// 0 means unlimited.
	budget int64
	// now is the clock for journal timestamps; tests inject a fixed one.
	now func() time.Time
	// writeJournal writes a journal atomically; tests inject failures (fault hooks, no
	// sleeps). Defaults to wire.WriteJournalAtomic.
	writeJournal func(path string, j wire.DurableJournal) error
}

// OpenStore prepares (creating if needed) the .sendbeam storage area for outDir and
// resolves every path so a later chdir cannot redirect writes.
func OpenStore(outDir string) (*DurableStore, error) {
	abs, err := filepath.Abs(outDir)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "durable: resolve out dir: %v", err)
	}
	root := filepath.Join(abs, durableDirName)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "durable: create %s: %v", root, err)
	}
	partialRoot := filepath.Join(root, durablePartialsDir)
	if err := os.MkdirAll(partialRoot, 0o700); err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "durable: create %s: %v", partialRoot, err)
	}
	return &DurableStore{
		outRoot:      abs,
		root:         root,
		partialRoot:  partialRoot,
		now:          time.Now,
		writeJournal: wire.WriteJournalAtomic,
	}, nil
}

// OutRoot returns the resolved absolute out directory the store lives under.
func (s *DurableStore) OutRoot() string { return s.outRoot }

// Root returns the resolved absolute .sendbeam directory.
func (s *DurableStore) Root() string { return s.root }

// Budget returns the partial-data byte budget (0 = unlimited).
func (s *DurableStore) Budget() int64 { return s.budget }

// SetBudget bounds how many bytes of partial data + journal a receive may checkpoint.
func (s *DurableStore) SetBudget(bytes int64) { s.budget = bytes }

// JournalPath returns the journal file path for one transfer id.
func (s *DurableStore) JournalPath(transferID string) string {
	return filepath.Join(s.root, transferID+".json")
}

// PartialDir returns the partial tree root for one transfer id (or temp id).
func (s *DurableStore) PartialDir(id string) string {
	return filepath.Join(s.partialRoot, id)
}

// PartialPath returns the .part path for one transfer id and canonical relative manifest
// path. rel must already be canonical (wire.NormalizeTransferPath).
func (s *DurableStore) PartialPath(id, rel string) string {
	return filepath.Join(s.partialRoot, id, filepath.FromSlash(rel)+durablePartSuffix)
}

// NewPartialID mints a fresh non-resumable partial-tree id for a manifest without a
// transfer id. Such partials are removed on abort (they can never be resumed) and only a
// hard crash can orphan them; orphans are surfaced by List.
func (s *DurableStore) NewPartialID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", wire.Errorf(wire.CodeStorage, "durable: random partial id: %v", err)
	}
	return durableTempPrefix + hex.EncodeToString(b), nil
}

// LoadJournal reads, decodes, and validates the journal for transferID. It returns
// (journal, false, nil) when no journal exists, and fails closed (error) when the file
// exists but is corrupt, torn, tampered, or from an unsupported version. Nothing is
// deleted on a load error: the journal is potentially resumable data.
func (s *DurableStore) LoadJournal(transferID string) (wire.DurableJournal, bool, error) {
	data, err := os.ReadFile(s.JournalPath(transferID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wire.DurableJournal{}, false, nil
		}
		return wire.DurableJournal{}, true, wire.Errorf(wire.CodeStorage, "durable: read journal: %v", err)
	}
	j, err := wire.DecodeJournal(data)
	if err != nil {
		return wire.DurableJournal{}, true, err
	}
	return j, true, nil
}

// SaveJournal writes a journal atomically through the configured writer (the default is
// temp + fsync + rename + best-effort dir fsync, so a crash leaves the old or the new
// journal, never a torn mix).
func (s *DurableStore) SaveJournal(j wire.DurableJournal) error {
	if err := s.writeJournal(s.JournalPath(j.TransferID), j); err != nil {
		return err
	}
	return nil
}

// partialsBackCheckpoint reports whether every committed file's .part is present and at
// least as long as its checkpoint claims (cheap Lstat; the authoritative check runs at
// resume time in Inspect/Prepare).
func (s *DurableStore) partialsBackCheckpoint(j *wire.DurableJournal) bool {
	for i, f := range j.Files {
		if f.CommittedBlocks == 0 {
			continue
		}
		want, err := j.CommittedBytes(i)
		if err != nil {
			return false
		}
		if err := checkSafePartial(s.PartialPath(j.TransferID, f.Name), want); err != nil {
			return false
		}
	}
	return true
}

// committedBytesTotal sums every file's durable byte claim (whole committed blocks,
// final block capped at file size).
func (s *DurableStore) committedBytesTotal(j *wire.DurableJournal) (int64, error) {
	var total int64
	for i := range j.Files {
		bytes, err := j.CommittedBytes(i)
		if err != nil {
			return 0, err
		}
		total += bytes
	}
	return total, nil
}

// journalSizeEstimate is the encoded size of a journal for disk-budget accounting; the
// checksum is recomputed at encode time, so this is a lower bound used only for budgeting.
func (s *DurableStore) journalSizeEstimate(j *wire.DurableJournal) int64 {
	if encoded, err := wire.EncodeJournal(*j); err == nil {
		return int64(len(encoded))
	}
	return 0
}

// DurableEntry is one row of the management list: a journal, an unreadable journal, or
// an orphaned partial tree.
type DurableEntry struct {
	// TransferID is the journal id, or the partial-tree name for orphans.
	TransferID string
	// JournalOK is false when a journal file exists but fails decode/validation, or for
	// orphaned partials. Such entries are surfaced, never deleted, and always discardable.
	JournalOK bool
	// Err is the fail-closed reason for an unreadable journal ("" when JournalOK).
	Err string
	// Orphaned is true when partials exist without any journal (never resumable directly;
	// discard is the only cleanup).
	Orphaned bool
	// Fingerprint is the journal's manifest fingerprint ("" for orphans/unreadable).
	Fingerprint string
	// HasResumeSecret is true when the journal carries the transfer-scoped resume
	// credential (V13-PR07); without it, authenticated cross-session resume is unavailable
	// (legacy pre-PR07 state). Never printed as a value.
	HasResumeSecret bool
	// PartialOK is true when every committed file's .part backs its checkpoint (cheap
	// Lstat check; the authoritative check runs on resume).
	PartialOK bool
	// Files / TotalSize / CommittedBytes / UpdatedAt summarize a valid journal.
	Files          int
	TotalSize      int64
	CommittedBytes int64
	UpdatedAt      int64
}

// List scans the store and returns every journal (valid or unreadable) plus orphaned
// partial trees. A single bad journal never hides the others and is never deleted.
func (s *DurableStore) List() ([]DurableEntry, error) {
	journals, err := os.ReadDir(s.root)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "durable: list %s: %v", s.root, err)
	}
	seen := make(map[string]bool, len(journals))
	var entries []DurableEntry
	for _, entry := range journals {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if id == "" {
			continue
		}
		seen[id] = true
		j, ok, loadErr := s.LoadJournal(id)
		if loadErr != nil || !ok {
			entries = append(entries, DurableEntry{
				TransferID: id,
				JournalOK:  false,
				Err:        loadErr.Error(),
			})
			continue
		}
		committed, _ := s.committedBytesTotal(&j)
		var total int64
		for _, f := range j.Files {
			total += f.Size
		}
		entries = append(entries, DurableEntry{
			TransferID:      id,
			JournalOK:       true,
			Fingerprint:     j.ManifestFingerprint,
			HasResumeSecret: j.ResumeSecret != nil,
			PartialOK:       s.partialsBackCheckpoint(&j),
			Files:           len(j.Files),
			TotalSize:       total,
			CommittedBytes:  committed,
			UpdatedAt:       j.UpdatedAt,
		})
	}
	// Orphaned partial trees: a partials/<name> directory with no journal. They are
	// surfaced so the user can discard them; they are never deleted automatically.
	partials, err := os.ReadDir(s.partialRoot)
	if err != nil {
		return nil, wire.Errorf(wire.CodeStorage, "durable: list partials: %v", err)
	}
	for _, entry := range partials {
		if !entry.IsDir() {
			continue
		}
		if seen[entry.Name()] {
			continue
		}
		entries = append(entries, DurableEntry{
			TransferID: entry.Name(),
			JournalOK:  false,
			Orphaned:   true,
			Err:        "orphaned partial data (no journal)",
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].TransferID < entries[j].TransferID })
	return entries, nil
}

// Inspect validates one journal and its partial data against the checkpoint claims,
// failing closed on any inconsistency without deleting anything.
type Inspect struct {
	Journal      wire.DurableJournal
	JournalPath  string
	PartialDir   string
	Resumable    bool
	Problems     []string
	Committed    int64
	Total        int64
	FilesChecked int
}

// Inspect loads one journal and cross-checks every committed file's partial data. It
// never deletes anything; a journal that fails to load is reported with its reason.
func (s *DurableStore) Inspect(transferID string) (*Inspect, error) {
	j, ok, err := s.LoadJournal(transferID)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, wire.Errorf(wire.CodeStorage, "durable: no journal or partials for %q", transferID)
	}
	committed, err := s.committedBytesTotal(&j)
	if err != nil {
		return nil, err
	}
	var total int64
	for _, f := range j.Files {
		total += f.Size
	}
	ins := &Inspect{
		Journal:     j,
		JournalPath: s.JournalPath(transferID),
		PartialDir:  s.PartialDir(transferID),
		Committed:   committed,
		Total:       total,
	}
	for i, f := range j.Files {
		if f.CommittedBlocks == 0 {
			continue
		}
		ins.FilesChecked++
		wantBytes, _ := j.CommittedBytes(i)
		part := s.PartialPath(transferID, f.Name)
		if err := checkSafePartial(part, wantBytes); err != nil {
			ins.Problems = append(ins.Problems, fmt.Sprintf("%s: %v", f.Name, err))
		}
	}
	ins.Resumable = len(ins.Problems) == 0
	return ins, nil
}

// Discard removes one transfer's journal and partial tree, idempotently and bounded to
// that transfer: it never touches other journals, partials, or the out directory. The
// journal is removed first so a failure leaves the partials in place for a retry; a
// repeat discard cleans up anything already removed.
func (s *DurableStore) Discard(transferID string) error {
	if transferID == "" || strings.ContainsAny(transferID, `/\`) {
		return wire.Errorf(wire.CodeStorage, "durable: invalid transfer id %q", transferID)
	}
	journalPath := s.JournalPath(transferID)
	if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return wire.Errorf(wire.CodeStorage, "durable: discard journal: %v", err)
	}
	if err := os.RemoveAll(s.PartialDir(transferID)); err != nil {
		return wire.Errorf(wire.CodeStorage, "durable: discard partials: %v", err)
	}
	return nil
}

// DiscardAll discards every journal and orphaned partial tree in the store. It is the
// explicit --all surface and never runs implicitly.
func (s *DurableStore) DiscardAll() error {
	entries, err := s.List()
	if err != nil {
		return err
	}
	var errs []error
	for _, entry := range entries {
		if err := s.Discard(entry.TransferID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// destinationIdentity binds a journal to one receive location: the canonical SHA-256 of
// the resolved absolute out directory. A journal copied into a different location fails
// this check and is rejected closed (ADR 0004 §3: revalidate user-editable claims).
func destinationIdentity(outRoot string) (wire.JournalIdentity, error) {
	abs, err := filepath.Abs(outRoot)
	if err != nil {
		return wire.JournalIdentity{}, err
	}
	sum := sha256.Sum256([]byte("sendbeam/destination-location\x00" + abs))
	return wire.JournalIdentity{Version: 1, Value: hex.EncodeToString(sum[:])}, nil
}

// unboundSourceIdentity is the PR02 source claim. Peer identity binding is PR07; until
// then the journal records a fixed, honest "source unbound" envelope so the schema's
// sourceIdentity requirement is met without inventing authentication.
func unboundSourceIdentity() wire.JournalIdentity {
	sum := sha256.Sum256([]byte("sendbeam/source-unbound-v1"))
	return wire.JournalIdentity{Version: 1, Value: hex.EncodeToString(sum[:])}
}

// durableHooks are deterministic fault-injection points for tests (no sleeps): they
// default to the real behavior and tests replace them to simulate crashes, torn writes,
// and quota at exact block boundaries.
type durableHooks struct {
	now          func() time.Time
	syncFile     func(f *os.File) error
	writeJournal func(path string, j wire.DurableJournal) error
	promote      func(partPath, finalPath string) error
}

// DurableDestination is the wire.Destination for CLI receives: verified blocks land in
// .part files under .sendbeam, each checkpoint is journaled only after its block is
// fsynced, and the final files appear only after whole-transfer verification, promoted
// atomically without overwriting. It preserves the path-safety, symlink, destination-root,
// and O_EXCL/no-overwrite guarantees of the destination it replaces.
type DurableDestination struct {
	store   *DurableStore
	outRoot string
	// partialID is the transfer's partial tree name: the transfer id when the manifest
	// opted into resumption, else a fresh tmp- name.
	partialID string

	mu       sync.Mutex
	prepared bool
	closed   bool
	aborted  bool
	// journal is nil for transfers whose manifest carried no transfer id (non-resumable).
	journal    *wire.DurableJournal
	transferID string
	resumed    bool
	// expectResume is set by the driver when this receive is an explicit authenticated-resume
	// attempt for a specific interrupted journal (V13-PR08: `sendbeam transfers resume`).
	// Until resume-auth succeeds in THIS session, that journal's progress is never trusted.
	expectResume string
	// resumeAuthorized records that mutual resume-auth completed in this session; only then
	// may a pre-existing journal's verified progress be reused.
	resumeAuthorized bool
	// sinks, finalPaths, partPaths key by manifest file index.
	sinks      map[int]*DurableFileSink
	finalPaths map[int]string
	partPaths  map[int]string
	// finalDirs are directories created under the out root; partDirs under the partial tree.
	finalDirs []string
	partDirs  []string

	hooks durableHooks
}

// NewDurableDestination prepares the .sendbeam store under outDir for one receive.
func NewDurableDestination(outDir string) (*DurableDestination, error) {
	store, err := OpenStore(outDir)
	if err != nil {
		return nil, err
	}
	return &DurableDestination{
		store:      store,
		outRoot:    store.OutRoot(),
		sinks:      make(map[int]*DurableFileSink),
		finalPaths: make(map[int]string),
		partPaths:  make(map[int]string),
		hooks: durableHooks{
			now:          store.now,
			syncFile:     func(f *os.File) error { return f.Sync() },
			writeJournal: store.writeJournal,
		},
	}, nil
}

// Store exposes the underlying storage area (management surfaces use it directly).
func (d *DurableDestination) Store() *DurableStore { return d.store }

// ExpectResume marks this receive as an explicit authenticated-resume attempt for the
// interrupted journal `transferID` (the user pre-selected it locally). Until resume-auth
// succeeds in this session, the journal's verified progress is never trusted.
func (d *DurableDestination) ExpectResume(transferID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expectResume = transferID
}

// SetResumeAuthorized records that mutual resume-auth completed in THIS session; only then
// may the pre-selected interrupted journal's verified progress be reused (V13-PR08
// invariant). A fresh receive without a pre-selected journal never needs it.
func (d *DurableDestination) SetResumeAuthorized() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.resumeAuthorized = true
}

// Prepare validates the manifest and establishes the journal: it loads and revalidates an
// existing journal for the manifest's transfer id (fail closed on corrupt, foreign, or
// mismatched state), or creates a fresh one. Transfers whose manifest carries no transfer
// id never opt into resumption and get no journal.
//
// V13-PR08 fail-closed gating: an existing journal's verified progress is reused ONLY when
// this session authenticated a resume for it (ExpectResume + SetResumeAuthorized). A plain
// receive that meets an interrupted journal — or an explicit resume attempt whose
// authentication never completed — fails closed with guidance; nothing is deleted and
// nothing is silently resumed.
func (d *DurableDestination) Prepare(manifest wire.Manifest) error {
	validated, err := wire.ValidateManifest(manifest)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.prepared {
		return wire.Errorf(wire.CodeStorage, "durable: destination prepared twice")
	}
	d.prepared = true
	for _, f := range validated.Files {
		// The .sendbeam storage directory lives at the out root; a manifest file claiming
		// that name would collide with it at finalize, so fail closed up front.
		if f.Name == durableDirName || strings.HasPrefix(f.Name, durableDirName+"/") {
			return wire.Errorf(wire.CodeProtocol,
				"transfer: manifest path %q collides with the %s storage directory", f.Name, durableDirName)
		}
	}
	if validated.TransferID == "" {
		id, err := d.store.NewPartialID()
		if err != nil {
			return err
		}
		d.partialID = id
		return d.ensurePartialBase()
	}
	d.transferID = validated.TransferID
	d.partialID = validated.TransferID
	existing, ok, loadErr := d.store.LoadJournal(validated.TransferID)
	if loadErr != nil {
		return wire.Errorf(wire.CodeStorage,
			"transfer: journal %s is unusable (%v); nothing was deleted — run \"sendbeam transfers inspect %s\" or discard it",
			validated.TransferID, loadErr, validated.TransferID)
	}
	if !ok {
		dest, err := destinationIdentity(d.outRoot)
		if err != nil {
			return err
		}
		j, err := wire.NewJournal(validated.TransferID, validated,
			unboundSourceIdentity(), dest, d.hooks.now())
		if err != nil {
			return err
		}
		d.journal = &j
		if err := d.store.SaveJournal(j); err != nil {
			return err
		}
		return d.ensurePartialBase()
	}
	// A journal exists: revalidate every user-editable claim against the authenticated
	// manifest before trusting it (ADR 0004 §3). A fingerprint mismatch means the id was
	// reused for a different file set; never guess.
	fp, err := wire.ManifestFingerprint(validated)
	if err != nil {
		return err
	}
	if existing.ManifestFingerprint != fp {
		return wire.Errorf(wire.CodeStorage,
			"transfer: journal %s does not match the authenticated manifest (fingerprint mismatch); refusing to guess — run \"sendbeam transfers inspect %s\" or discard it",
			validated.TransferID, validated.TransferID)
	}
	// V13-PR08: an interrupted journal's verified progress may be reused ONLY after
	// successful resume-auth in this session. A fresh rendezvous authenticates the NEW
	// session only; it does not prove continuity with the original transfer peer. Failing
	// closed here is what makes a fresh session unable to skip old blocks merely because
	// the transfer id + fingerprint match.
	if !d.resumeAuthorized {
		// The pre-selected-journal branch fires only when the incoming manifest IS the
		// interrupted journal the user chose; a different id means a fresh sender and is
		// handled by the generic branch below (its journal, if any, still fails closed).
		if d.expectResume != "" && d.expectResume == validated.TransferID {
			return wire.Errorf(wire.CodeStorage,
				"transfer: resume of %s was not authenticated in this session; refusing to reuse its verified progress — nothing was received or deleted. Re-run \"sendbeam transfers resume %s --code <fresh code>\" so both peers authenticate first",
				validated.TransferID, validated.TransferID)
		}
		return wire.Errorf(wire.CodeStorage,
			"transfer: transfer %s has verified partial data kept from an interrupted transfer; resuming it requires authenticated resume. Run \"sendbeam transfers resume %s --code <fresh code>\" (the sender re-runs its send for a fresh code), or discard the state with \"sendbeam transfers discard %s --out %s\" to receive fresh — nothing was received or deleted",
			validated.TransferID, validated.TransferID, validated.TransferID, d.outRoot)
	}
	wantDest, err := destinationIdentity(d.outRoot)
	if err != nil {
		return err
	}
	if existing.DestinationIdentity != wantDest {
		return wire.Errorf(wire.CodeStorage,
			"transfer: journal %s was created for a different destination location; refusing to resume — run \"sendbeam transfers inspect %s\" or discard it",
			validated.TransferID, validated.TransferID)
	}
	d.journal = &existing
	d.resumed = true
	return d.ensurePartialBase()
}

// ensurePartialBase creates the transfer's partial tree root so a file without sub-
// directories can be opened directly under it (buildDirPath only creates sub-components).
func (d *DurableDestination) ensurePartialBase() error {
	base := d.store.PartialDir(d.partialID)
	if err := os.MkdirAll(base, 0o700); err != nil {
		return wire.Errorf(wire.CodeStorage, "durable: create partial tree: %v", err)
	}
	return nil
}

// buildDirPath walks a canonical relative path under base, refusing symlinked or
// non-directory components and creating only missing safe directories. It appends created
// directories to created so finalize can remove the empty ones.
func (d *DurableDestination) buildDirPath(base, rel string, created *[]string) (string, error) {
	parts := strings.Split(rel, "/")
	parent := base
	for _, part := range parts[:len(parts)-1] {
		parent = filepath.Join(parent, part)
		info, statErr := os.Lstat(parent)
		if errors.Is(statErr, os.ErrNotExist) {
			if err := os.Mkdir(parent, 0o755); err != nil {
				return "", err
			}
			*created = append(*created, parent)
			continue
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", fmt.Errorf("transfer: destination component is not a safe directory: %s", parent)
		}
	}
	return filepath.Join(parent, parts[len(parts)-1]), nil
}

// withinRoot guards a resolved path against escaping its root (defense in depth: the
// manifest path was already canonicalized, and the components were checked above).
func withinRoot(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Open creates the .part sink for one manifest file. On a resumed transfer it opens the
// existing partial and truncates it to the journal's authoritative checkpoint
// (committedBytes), so unclaimed stale tail bytes from a crash between write and journal
// commit are dropped and safely re-transferred; missing or short partials fail closed.
func (d *DurableDestination) Open(file wire.FileEntry) (wire.Sink, error) {
	name, err := wire.NormalizeTransferPath(file.Name)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.aborted {
		return nil, errSinkClosed
	}
	if !d.prepared {
		return nil, wire.Errorf(wire.CodeStorage, "durable: Open before Prepare")
	}
	if _, dup := d.sinks[file.Idx]; dup {
		return nil, wire.Errorf(wire.CodeStorage, "durable: file %d opened twice", file.Idx)
	}
	final, err := d.buildDirPath(d.outRoot, name, &d.finalDirs)
	if err != nil {
		return nil, err
	}
	if !withinRoot(d.outRoot, final) {
		return nil, errors.New("transfer: destination path escaped its root")
	}
	part, err := d.buildDirPath(d.store.PartialDir(d.partialID), name, &d.partDirs)
	if err != nil {
		return nil, err
	}
	if !withinRoot(d.store.PartialDir(d.partialID), part) {
		return nil, errors.New("transfer: partial path escaped its root")
	}
	part += durablePartSuffix

	var committed int64
	if d.journal != nil {
		committed, err = d.journal.CommittedBytes(file.Idx)
		if err != nil {
			return nil, err
		}
	}
	var f *os.File
	switch {
	case d.resumed && d.journal != nil && committed > 0:
		// Resume with a checkpoint: the partial must back the journal's claim. The path is
		// checked with Lstat so a symlink or special file can never be truncated through,
		// then the file is truncated to the authoritative checkpoint — unclaimed stale
		// tail bytes from a crash between write and journal commit are dropped and safely
		// re-transferred; missing or short partials fail closed.
		if err := checkSafePartial(part, committed); err != nil {
			return nil, wire.Errorf(wire.CodeStorage,
				"transfer: journal %s file %q: %v — refusing to guess; run \"sendbeam transfers inspect %s\"",
				d.transferID, file.Name, err, d.transferID)
		}
		f, err = os.OpenFile(part, os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
		if err := f.Truncate(committed); err != nil {
			_ = f.Close()
			return nil, err
		}
	case d.resumed && d.journal != nil:
		// committed == 0: the file never checkpointed. A leftover partial (from a crash
		// before the first journal commit) is reused only when it is a safe regular file
		// and truncated to zero; otherwise the partial is created fresh with O_EXCL.
		if _, statErr := os.Lstat(part); statErr == nil {
			if err := checkSafePartial(part, 0); err != nil {
				return nil, err
			}
			f, err = os.OpenFile(part, os.O_RDWR, 0o600)
			if err != nil {
				return nil, err
			}
			if err := f.Truncate(0); err != nil {
				_ = f.Close()
				return nil, err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		} else {
			f, err = os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
			if err != nil {
				return nil, err
			}
		}
	default:
		// Fresh partial: O_EXCL so a stale leftover can never be silently reused.
		f, err = os.OpenFile(part, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			return nil, err
		}
	}
	sink := &DurableFileSink{
		dest: d, fileIdx: file.Idx, path: part, f: f,
		blockSize: file.BlockSize, syncFile: d.hooks.syncFile,
	}
	d.sinks[file.Idx] = sink
	d.finalPaths[file.Idx] = final
	d.partPaths[file.Idx] = part
	return sink, nil
}

// commitBlocks advances one file's checkpoint after its block data is durable, enforcing
// the disk budget at the same point. It is the only place the journal's committed
// progress may move forward (wire.CommitBlocks refuses regression and out-of-bounds).
// The optional digest state (V13-PR05), when non-empty, is persisted atomically with the
// checkpoint as a JournalDigestCheckpoint covering exactly these blocks; when empty, any
// stale checkpoint for the file is cleared (it could not cover the new high-water mark).
func (d *DurableDestination) commitBlocks(fileIdx, blocks int, digestState []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || d.aborted {
		return errSinkClosed
	}
	if d.journal == nil {
		return nil // non-resumable transfer: nothing to checkpoint
	}
	if err := d.journal.CommitBlocks(fileIdx, blocks, d.hooks.now()); err != nil {
		return err
	}
	var cp *wire.JournalDigestCheckpoint
	if len(digestState) > 0 {
		committed, err := d.journal.CommittedBytes(fileIdx)
		if err != nil {
			return err
		}
		cp = &wire.JournalDigestCheckpoint{
			Format:          wire.DigestCheckpointFormatGoStdlib,
			CommittedBlocks: blocks,
			CommittedBytes:  committed,
			State:           hex.EncodeToString(digestState),
		}
	}
	if err := d.journal.SetDigestCheckpoint(fileIdx, cp); err != nil {
		return err
	}
	committed, err := d.store.committedBytesTotal(d.journal)
	if err != nil {
		return err
	}
	if budget := d.store.Budget(); budget > 0 && committed+d.store.journalSizeEstimate(d.journal) > budget {
		return wire.NewTransferError(wire.FailQuota,
			fmt.Sprintf("durable storage budget of %d bytes exceeded; partial data is kept and resumable", budget))
	}
	// The checkpoint may only be persisted through the same atomic journal writer that
	// tests hook for deterministic crash injection.
	return d.hooks.writeJournal(d.store.JournalPath(d.transferID), *d.journal)
}

// AttachResumeSecret derives the transfer-scoped resume credential from the resume root of
// the ORIGINAL authenticated session and persists it into the receive journal (V13-PR07).
// It runs only after the manifest has been validated and bound to the journal, strictly
// before that credential can authorize a future cross-session resume.
//
// Provenance (V13-PR07 security review, Blocker 1): the credential may be derived only for
// a journal created during THIS manifest/session (`Prepare` did not load one). A journal
// loaded as existing/resumed state must NEVER receive a credential fabricated from a later
// session master: an existing credential is preserved exactly, a missing one stays missing.
// A non-resumable transfer (no journal) simply has nothing to attach.
func (d *DurableDestination) AttachResumeSecret(manifest wire.Manifest, resumeRoot []byte) error {
	validated, err := wire.ValidateManifest(manifest)
	if err != nil {
		return err
	}
	if validated.TransferID == "" {
		return nil // non-resumable transfer: no journal, no credential
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.journal == nil || d.journal.TransferID != validated.TransferID {
		return wire.Errorf(wire.CodeStorage,
			"durable: no journal for %s; refusing to attach a resume credential", validated.TransferID)
	}
	// The binding is validated FIRST so a manifest that does not match the journal fails
	// closed even when a credential is already persisted (fail-closed ordering).
	fp, err := wire.ManifestFingerprint(validated)
	if err != nil {
		return err
	}
	if d.journal.ManifestFingerprint != fp {
		return wire.Errorf(wire.CodeStorage,
			"durable: journal %s does not match the authenticated manifest; refusing to attach a resume credential",
			validated.TransferID)
	}
	if d.journal.ResumeSecret != nil {
		return nil // original-session credential already persisted; never replace it
	}
	if d.resumed {
		// The journal predates this session (loaded, not created): a missing credential
		// stays missing — never fabricated from a later session master. Old partials are
		// never deleted and the journal remains usable for its existing capabilities.
		return nil
	}
	secret, err := wire.ResumeSecret(resumeRoot, wire.ResumeAuthVersion, validated.TransferID, fp)
	if err != nil {
		return err
	}
	env, err := wire.EncodeResumeSecretEnvelope(secret)
	if err != nil {
		return err
	}
	d.journal.ResumeSecret = &wire.JournalResumeSecret{Version: env.Version, Value: env.Value}
	// Persist through the same atomic journal writer tests hook for crash injection, so
	// the credential is durable before it can authorize anything.
	return d.hooks.writeJournal(d.store.JournalPath(d.transferID), *d.journal)
}

// ResumeStateFor binds the loaded journal against the authenticated manifest and builds
// the wire receiver's resume seed: per-file high-water marks plus a digest re-hashed from
// the persisted prefix. Missing or truncated partials fail closed (never guessed, never
// deleted). Returns nil when the transfer is not resumable (no journal).
//
// V13-PR08: the seed may only be advertised after resume-auth succeeded in this session
// (Prepare already fails closed otherwise; this is defense in depth).
func (d *DurableDestination) ResumeStateFor(manifest wire.Manifest) (*wire.ReceiverResume, error) {
	d.mu.Lock()
	journal := d.journal
	authorized := d.resumeAuthorized
	expected := d.expectResume
	d.mu.Unlock()
	if journal == nil {
		return nil, nil
	}
	// The gate protects the PRE-SELECTED interrupted journal only: a manifest whose id
	// differs from the expected resume id is a genuinely fresh sender, and its fresh
	// journal has no verified progress at risk. Expected must equal the journal's id for
	// this to be the interrupted transfer the user chose.
	if !authorized && expected != "" && expected == journal.TransferID {
		return nil, wire.Errorf(wire.CodeStorage,
			"transfer: refusing to advertise verified progress for %s before resume authentication completed",
			journal.TransferID)
	}
	fp, err := wire.ManifestFingerprint(manifest)
	if err != nil {
		return nil, err
	}
	if journal.ManifestFingerprint != fp {
		return nil, wire.Errorf(wire.CodeStorage,
			"transfer: journal %s does not match the authenticated manifest; refusing to resume", journal.TransferID)
	}
	resume := &wire.ReceiverResume{
		TransferID:          journal.TransferID,
		ManifestFingerprint: journal.ManifestFingerprint,
		Files:               make(map[int]wire.ResumeFileProgress),
	}
	for i, f := range journal.Files {
		committed, err := journal.CommittedBytes(i)
		if err != nil {
			return nil, err
		}
		if f.CommittedBlocks == 0 {
			resume.Files[i] = wire.ResumeFileProgress{HaveBlocks: 0}
			continue
		}
		part := d.store.PartialPath(journal.TransferID, f.Name)
		if err := checkSafePartial(part, committed); err != nil {
			return nil, wire.Errorf(wire.CodeStorage,
				"transfer: journal %s file %q: %v — refusing to resume; run \"sendbeam transfers inspect %s\"",
				journal.TransferID, f.Name, err, journal.TransferID)
		}
		// V13-PR05: restore the digest from the checkpointed state when this runtime
		// produced it and it decodes; otherwise correctness-first, re-hash the persisted
		// prefix. Final whole-file verification is mandatory in every path, so an
		// unrestorable or wrong state can never corrupt — it would fail verification.
		var digest wire.Digest
		restored := false
		if cp := f.DigestCheckpoint; cp != nil && cp.Format == wire.DigestCheckpointFormatGoStdlib {
			if state, err := hex.DecodeString(cp.State); err == nil {
				if digest, err = wire.RestoreSHA256Digest(state); err == nil {
					restored = true
				}
			}
		}
		if !restored {
			digest = wire.NewSHA256Digest()
			if err := hashPrefix(part, committed, digest); err != nil {
				return nil, err
			}
		}
		resume.Files[i] = wire.ResumeFileProgress{HaveBlocks: f.CommittedBlocks, SeedDigest: digest}
	}
	return resume, nil
}

// checkSafePartial verifies a .part path is a regular file (never a symlink or special
// file — a symlink would let a truncated open write through it) and, when wantBytes > 0,
// that it is at least that long, so the journal's checkpoint claim is backed by durable
// data. Missing or short partials fail closed.
func checkSafePartial(part string, wantBytes int64) error {
	info, err := os.Lstat(part)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return wire.Errorf(wire.CodeStorage, "partial data missing (%s)", part)
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return wire.Errorf(wire.CodeStorage, "partial path is not a safe regular file (%s)", part)
	}
	if wantBytes > 0 && info.Size() < wantBytes {
		return wire.Errorf(wire.CodeStorage,
			"partial truncated (have %d bytes, checkpoint claims %d)", info.Size(), wantBytes)
	}
	return nil
}

// hashPrefix feeds the first n bytes of path into digest — the correctness-first restore
// for PR02: the persisted prefix is re-hashed on resume rather than trusting stored
// digest state (V13-PR05 may later checkpoint digest state safely).
func hashPrefix(path string, n int64, digest wire.Digest) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	remaining := n
	buf := make([]byte, 64*1024)
	for remaining > 0 {
		chunk := buf
		if int64(len(chunk)) > remaining {
			chunk = buf[:remaining]
		}
		read, err := f.Read(chunk)
		if read > 0 {
			digest.Update(chunk[:read])
			remaining -= int64(read)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		if read == 0 {
			break
		}
	}
	if remaining > 0 {
		return wire.Errorf(wire.CodeStorage, "durable: partial prefix truncated while hashing")
	}
	return nil
}

// Close finalizes the receive: it runs only after the wire layer verified the whole
// transfer, then atomically promotes every .part file to its final name (no-overwrite)
// and removes the journal. Any failure leaves the partials and journal intact for
// inspection/discard — final files are never left half-verified.
func (d *DurableDestination) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	finals := make(map[int]string, len(d.finalPaths))
	parts := make(map[int]string, len(d.partPaths))
	for idx, path := range d.finalPaths {
		finals[idx] = path
	}
	for idx, path := range d.partPaths {
		parts[idx] = path
	}
	transferID := d.transferID
	journal := d.journal
	d.mu.Unlock()

	idxOrder := make([]int, 0, len(parts))
	for idx := range parts {
		idxOrder = append(idxOrder, idx)
	}
	sort.Ints(idxOrder)
	for _, idx := range idxOrder {
		if err := d.promote(parts[idx], finals[idx]); err != nil {
			return err
		}
	}
	if journal != nil {
		// The journal is removed only after every final rename is in place: a crash in
		// between leaves a fully-committed journal plus finals, which inspect/discard
		// surface; removing the journal first would orphan the checkpoint entirely.
		if err := d.store.Discard(transferID); err != nil {
			return err
		}
	} else {
		// Non-resumable transfer: drop its temp partial tree now that finals exist.
		if err := os.RemoveAll(d.store.PartialDir(d.partialID)); err != nil {
			return err
		}
	}
	// Best-effort cleanup: remove now-empty partial dirs and the out-root dirs that only
	// held finals (finals are already renamed into place).
	for i := len(d.partDirs) - 1; i >= 0; i-- {
		_ = os.Remove(d.partDirs[i])
	}
	for i := len(d.finalDirs) - 1; i >= 0; i-- {
		_ = os.Remove(d.finalDirs[i])
	}
	syncDir(d.outRoot)
	return nil
}

// promote atomically renames a verified .part into its final name without overwriting:
// hard-link (atomic no-clobber on POSIX and NTFS) then unlink the .part; filesystems
// without hard links fall back to a checked rename. Existing destinations fail closed.
func (d *DurableDestination) promote(part, final string) error {
	if d.hooks.promote != nil {
		return d.hooks.promote(part, final)
	}
	return promoteFile(part, final)
}

func promoteFile(part, final string) error {
	if err := os.Link(part, final); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("transfer: destination %q already exists; refusing to overwrite", final)
		}
		// Hard links unsupported (FAT/exFAT): checked rename fallback. The check is not a
		// trust anchor against a concurrent local attacker, but the transfer already
		// failed closed at Open for any pre-existing destination; this guards the common
		// case on linkless filesystems.
		if _, statErr := os.Lstat(final); statErr == nil {
			return fmt.Errorf("transfer: destination %q already exists; refusing to overwrite", final)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return statErr
		}
		if err := os.Rename(part, final); err != nil {
			return err
		}
		return nil
	}
	if err := os.Remove(part); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Abort closes every open sink and — for resumable transfers — deliberately KEEPS the
// partials and journal at their last durable checkpoint: they are the user's only
// resumable data and are never silently deleted (ADR 0004 §8). Only a non-resumable
// transfer's temp partials are removed here, since no journal can ever claim them.
func (d *DurableDestination) Abort(reason string) error {
	d.mu.Lock()
	if d.closed || d.aborted {
		d.mu.Unlock()
		return nil
	}
	d.aborted = true
	sinks := make([]*DurableFileSink, 0, len(d.sinks))
	for _, sink := range d.sinks {
		sinks = append(sinks, sink)
	}
	journal := d.journal
	partialID := d.partialID
	d.mu.Unlock()
	for _, sink := range sinks {
		_ = sink.Abort(reason)
	}
	// Only a non-resumable transfer's OWN temp partial tree is removed. partialID is ""
	// when the manifest never arrived (e.g. the sender died during resume auth): PartialDir("")
	// would resolve to the shared partials ROOT, so removing it would destroy EVERY
	// transfer's partial data. Never touch anything in that state.
	if journal == nil && partialID != "" {
		_ = os.RemoveAll(d.store.PartialDir(partialID))
	}
	return nil
}

// Path returns the final destination path assigned to one manifest index.
func (d *DurableDestination) Path(fileIdx int) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.finalPaths[fileIdx]
}

// syncDir fsyncs a directory so a rename inside it is durable. POSIX only; Windows and
// filesystems that reject directory sync are best-effort (matching wire.WriteJournalAtomic).
func syncDir(dir string) {
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	defer func() { _ = d.Close() }()
	_ = d.Sync()
}

// DurableFileSink is a wire.Sink over one .part file. Write implements the durability
// ordering: data write, fsync barrier, then checkpoint advancement — the ack that
// advertises progress is only sent by the wire layer after Write returns.
type DurableFileSink struct {
	dest      *DurableDestination
	fileIdx   int
	path      string
	f         *os.File
	blockSize int
	syncFile  func(f *os.File) error

	mu                 sync.Mutex
	closed             bool
	pendingDigestState []byte
}

// Path returns the .part path (never a final name).
func (s *DurableFileSink) Path() string { return s.path }

// SetDigestState implements wire.DigestStateSink (V13-PR05): the serialized digest state
// covering exactly the blocks the next Write checkpoints is carried into the same atomic
// journal update. A nil state clears it (the next checkpoint carries no digest state and
// resume re-hashes). The receiver calls this before each Write, so a stale state is
// impossible: every commit consumes the state that was set for exactly its blocks.
func (s *DurableFileSink) SetDigestState(state []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	s.pendingDigestState = state
	return nil
}

// Write places one verified block at offset and, only after fsyncing it, advances the
// journal checkpoint for the completed block. The block must be block-aligned (the wire
// layer guarantees this), so the checkpoint is offset/blockSize + 1 whole blocks. The
// pending digest state set before this call is persisted atomically with the checkpoint.
func (s *DurableFileSink) Write(offset int64, bytes []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSinkClosed
	}
	if _, err := s.f.WriteAt(bytes, offset); err != nil {
		return err
	}
	// Durability barrier: the data must reach stable storage before the checkpoint may
	// advance (ADR 0004 §1).
	if err := s.syncFile(s.f); err != nil {
		return err
	}
	blocks := int(offset/int64(s.blockSize)) + 1
	state := s.pendingDigestState
	s.pendingDigestState = nil
	return s.dest.commitBlocks(s.fileIdx, blocks, state)
}

// Close flushes and closes the .part descriptor. It is idempotent. The final rename is
// performed later by DurableDestination.Close after whole-transfer verification.
func (s *DurableFileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := s.f.Sync(); err != nil {
		return err
	}
	return s.f.Close()
}

// Abort closes the descriptor but KEEPS the .part file: it is resumable data and is only
// removed by an explicit discard (or by finalize's rename). Idempotent.
func (s *DurableFileSink) Abort(_ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.f.Close()
}
