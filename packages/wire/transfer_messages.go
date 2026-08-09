package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// JSON codec for the transfer control messages (design §5.4). These travel as the plaintext
// inside AES-GCM frames whose header Type names the message; block_data is raw file bytes and
// is not handled here. It is the Go twin of packages/protocol/src/transfer-messages.ts and
// must be byte-identical on the wire: field declaration order matches the TS object-literal
// order (so JSON keys serialize in the same sequence), and HTML escaping is disabled so
// characters like <, >, and & in a filename encode the same as JavaScript's JSON.stringify.

// ControlMsg is one decoded transfer control message. Callers type-switch on the concrete
// type; FrameType reports the frame-header tag to stamp when sending it.
type ControlMsg interface {
	FrameType() uint8
}

// FileEntry is one file's metadata within a manifest.
type FileEntry struct {
	Idx          int    `json:"idx"`
	Name         string `json:"name"` // sanitized on receipt
	Size         int64  `json:"size"`
	Mime         string `json:"mime"`
	LastModified int64  `json:"lastModified"`
	BlockSize    int    `json:"blockSize"`
	Blocks       int    `json:"blocks"`
	FileDigest   string `json:"fileDigest"` // canonical whole-file SHA-256 (hex)
}

// Manifest lists the files a transfer will deliver.
type Manifest struct {
	Type      uint8       `json:"type"`
	Files     []FileEntry `json:"files"`
	TotalSize int64       `json:"totalSize"`
}

// BlockHash carries a block's SHA-256 so the receiver can verify before acking.
type BlockHash struct {
	Type     uint8  `json:"type"`
	FileIdx  int    `json:"fileIdx"`
	BlockIdx int    `json:"blockIdx"`
	SHA256   string `json:"sha256"`
}

// BlockRecv is the legacy pre-verification receipt retained for decoder compatibility.
type BlockRecv struct {
	Type     uint8 `json:"type"`
	FileIdx  int   `json:"fileIdx"`
	BlockIdx int   `json:"blockIdx"`
}

// Ack confirms that a block was verified and committed to the destination sink.
type Ack struct {
	Type     uint8 `json:"type"`
	FileIdx  int   `json:"fileIdx"`
	BlockIdx int   `json:"blockIdx"`
}

// Nack requests a fresh transmission of a block that did not arrive.
type Nack struct {
	Type     uint8      `json:"type"`
	FileIdx  int        `json:"fileIdx"`
	BlockIdx int        `json:"blockIdx"`
	Reason   NackReason `json:"reason"`
}

// NackReason describes why a block is being requested again.
type NackReason string

const (
	// NackMissing means a later block exposed a gap in the ordered block sequence.
	NackMissing NackReason = "missing"
	// NackTimeout means the acknowledgement deadline expired.
	NackTimeout NackReason = "timeout"
)

// Control changes the live transfer state in either direction.
type Control struct {
	Type uint8     `json:"type"`
	Op   ControlOp `json:"op"`
}

// ControlOp is one bidirectional transfer action.
type ControlOp string

const (
	// ControlPause stops creation of new outbound data frames.
	ControlPause ControlOp = "pause"
	// ControlResume allows outbound data frames again.
	ControlResume ControlOp = "resume"
	// ControlCancel terminates the transfer.
	ControlCancel ControlOp = "cancel"
)

// Complete tells the receiver every block was sent and gives the canonical digest to verify.
type Complete struct {
	Type       uint8  `json:"type"`
	FileDigest string `json:"fileDigest"`
}

// Done is the receiver's confirmation that verification succeeded.
type Done struct {
	Type uint8 `json:"type"`
}

// Fail aborts the transfer with a machine-readable reason.
type Fail struct {
	Type   uint8      `json:"type"`
	Reason FailReason `json:"reason"`
}

// FrameType returns the frame-header tag for each message; the JSON "type" field carries the
// same value, so the field is the single source of truth and cannot drift from the header.
func (m Manifest) FrameType() uint8 { return m.Type }

// FrameType reports the block_hash frame tag.
func (m BlockHash) FrameType() uint8 { return m.Type }

// FrameType reports the block_recv frame tag.
func (m BlockRecv) FrameType() uint8 { return m.Type }

// FrameType reports the ack frame tag.
func (m Ack) FrameType() uint8 { return m.Type }

// FrameType reports the nack frame tag.
func (m Nack) FrameType() uint8 { return m.Type }

// FrameType reports the control frame tag.
func (m Control) FrameType() uint8 { return m.Type }

// FrameType reports the complete frame tag.
func (m Complete) FrameType() uint8 { return m.Type }

// FrameType reports the done frame tag.
func (m Done) FrameType() uint8 { return m.Type }

// FrameType reports the fail frame tag.
func (m Fail) FrameType() uint8 { return m.Type }

// NewManifest builds a manifest message with the correct frame tag.
func NewManifest(files []FileEntry, totalSize int64) *Manifest {
	return &Manifest{Type: FrameManifest, Files: files, TotalSize: totalSize}
}

// NewBlockHash builds a block_hash message.
func NewBlockHash(fileIdx, blockIdx int, sha256 string) *BlockHash {
	return &BlockHash{Type: FrameBlockHash, FileIdx: fileIdx, BlockIdx: blockIdx, SHA256: sha256}
}

// NewBlockRecv builds a legacy pre-verification receipt.
func NewBlockRecv(fileIdx, blockIdx int) *BlockRecv {
	return &BlockRecv{Type: FrameBlockRecv, FileIdx: fileIdx, BlockIdx: blockIdx}
}

// NewAck builds a verified-block acknowledgement.
func NewAck(fileIdx, blockIdx int) *Ack {
	return &Ack{Type: FrameAck, FileIdx: fileIdx, BlockIdx: blockIdx}
}

// NewNack builds a missing-block request.
func NewNack(fileIdx, blockIdx int, reason NackReason) *Nack {
	return &Nack{Type: FrameNack, FileIdx: fileIdx, BlockIdx: blockIdx, Reason: reason}
}

// NewControl builds a bidirectional transfer control message.
func NewControl(op ControlOp) *Control { return &Control{Type: FrameControl, Op: op} }

// NewComplete builds a complete message carrying the canonical file digest.
func NewComplete(fileDigest string) *Complete {
	return &Complete{Type: FrameComplete, FileDigest: fileDigest}
}

// NewDone builds a done message.
func NewDone() *Done { return &Done{Type: FrameDone} }

// NewFail builds a fail message with the given reason.
func NewFail(reason FailReason) *Fail { return &Fail{Type: FrameFail, Reason: reason} }

// EncodeControl serializes a control message to its wire JSON. HTML escaping is disabled and
// the encoder's trailing newline stripped so the bytes match JavaScript's JSON.stringify.
func EncodeControl(msg ControlMsg) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(msg); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// DecodeControl parses a control-frame payload, validating shape so a decrypted-but-malformed
// frame fails loudly rather than corrupting state. block_data is never passed here.
func DecodeControl(payload []byte) (ControlMsg, error) {
	var head struct {
		Type *int `json:"type"`
	}
	if err := json.Unmarshal(payload, &head); err != nil {
		return nil, errors.New("control frame: invalid JSON")
	}
	if head.Type == nil {
		return nil, errors.New("control frame: missing type")
	}
	if *head.Type < 0 || *head.Type > 0xff {
		return nil, fmt.Errorf("control frame: invalid type %d", *head.Type)
	}
	switch uint8(*head.Type) {
	case FrameManifest:
		return decodeManifest(payload)
	case FrameBlockHash:
		return decodeBlockHash(payload)
	case FrameBlockRecv:
		return decodeBlockRecv(payload)
	case FrameAck:
		return decodeAck(payload)
	case FrameNack:
		return decodeNack(payload)
	case FrameControl:
		return decodeControlMessage(payload)
	case FrameComplete:
		return decodeComplete(payload)
	case FrameDone:
		return &Done{Type: FrameDone}, nil
	case FrameFail:
		return decodeFail(payload)
	default:
		return nil, fmt.Errorf("control frame: unexpected type %d", *head.Type)
	}
}

// rawFileEntry mirrors FileEntry with pointer fields so a missing key is distinguishable from
// a legitimate zero value (e.g. idx 0), matching the TS num()/str() presence checks.
type rawFileEntry struct {
	Idx          *int    `json:"idx"`
	Name         *string `json:"name"`
	Size         *int64  `json:"size"`
	Mime         *string `json:"mime"`
	LastModified *int64  `json:"lastModified"`
	BlockSize    *int    `json:"blockSize"`
	Blocks       *int    `json:"blocks"`
	FileDigest   *string `json:"fileDigest"`
}

func (r rawFileEntry) build() (FileEntry, error) {
	if r.Idx == nil || r.Name == nil || r.Size == nil || r.Mime == nil ||
		r.LastModified == nil || r.BlockSize == nil || r.Blocks == nil || r.FileDigest == nil {
		return FileEntry{}, errors.New("control frame: incomplete file entry")
	}
	return FileEntry{
		Idx: *r.Idx, Name: *r.Name, Size: *r.Size, Mime: *r.Mime,
		LastModified: *r.LastModified, BlockSize: *r.BlockSize, Blocks: *r.Blocks,
		FileDigest: *r.FileDigest,
	}, nil
}

func decodeManifest(payload []byte) (ControlMsg, error) {
	var raw struct {
		Files     []rawFileEntry `json:"files"`
		TotalSize *int64         `json:"totalSize"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid manifest")
	}
	if len(raw.Files) == 0 {
		return nil, errors.New("control frame: manifest.files empty")
	}
	if raw.TotalSize == nil {
		return nil, errors.New("control frame: manifest.totalSize missing")
	}
	files := make([]FileEntry, len(raw.Files))
	for i, rf := range raw.Files {
		f, err := rf.build()
		if err != nil {
			return nil, err
		}
		files[i] = f
	}
	return &Manifest{Type: FrameManifest, Files: files, TotalSize: *raw.TotalSize}, nil
}

func decodeBlockHash(payload []byte) (ControlMsg, error) {
	var raw struct {
		FileIdx  *int    `json:"fileIdx"`
		BlockIdx *int    `json:"blockIdx"`
		SHA256   *string `json:"sha256"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid block_hash")
	}
	if raw.FileIdx == nil || raw.BlockIdx == nil || raw.SHA256 == nil {
		return nil, errors.New("control frame: incomplete block_hash")
	}
	return &BlockHash{Type: FrameBlockHash, FileIdx: *raw.FileIdx, BlockIdx: *raw.BlockIdx, SHA256: *raw.SHA256}, nil
}

func decodeBlockRecv(payload []byte) (ControlMsg, error) {
	var raw struct {
		FileIdx  *int `json:"fileIdx"`
		BlockIdx *int `json:"blockIdx"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid block_recv")
	}
	if raw.FileIdx == nil || raw.BlockIdx == nil {
		return nil, errors.New("control frame: incomplete block_recv")
	}
	return &BlockRecv{Type: FrameBlockRecv, FileIdx: *raw.FileIdx, BlockIdx: *raw.BlockIdx}, nil
}

func decodeAck(payload []byte) (ControlMsg, error) {
	var raw struct {
		FileIdx  *int `json:"fileIdx"`
		BlockIdx *int `json:"blockIdx"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid ack")
	}
	if raw.FileIdx == nil || raw.BlockIdx == nil {
		return nil, errors.New("control frame: incomplete ack")
	}
	return &Ack{Type: FrameAck, FileIdx: *raw.FileIdx, BlockIdx: *raw.BlockIdx}, nil
}

func decodeNack(payload []byte) (ControlMsg, error) {
	var raw struct {
		FileIdx  *int    `json:"fileIdx"`
		BlockIdx *int    `json:"blockIdx"`
		Reason   *string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid nack")
	}
	if raw.FileIdx == nil || raw.BlockIdx == nil || raw.Reason == nil {
		return nil, errors.New("control frame: incomplete nack")
	}
	reason := NackReason(*raw.Reason)
	if reason != NackMissing && reason != NackTimeout {
		return nil, fmt.Errorf("control frame: bad nack reason %q", *raw.Reason)
	}
	return &Nack{Type: FrameNack, FileIdx: *raw.FileIdx, BlockIdx: *raw.BlockIdx, Reason: reason}, nil
}

func decodeControlMessage(payload []byte) (ControlMsg, error) {
	var raw struct {
		Op *string `json:"op"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid control")
	}
	if raw.Op == nil {
		return nil, errors.New("control frame: control.op missing")
	}
	op := ControlOp(*raw.Op)
	if op != ControlPause && op != ControlResume && op != ControlCancel {
		return nil, fmt.Errorf("control frame: bad control op %q", *raw.Op)
	}
	return &Control{Type: FrameControl, Op: op}, nil
}

func decodeComplete(payload []byte) (ControlMsg, error) {
	var raw struct {
		FileDigest *string `json:"fileDigest"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid complete")
	}
	if raw.FileDigest == nil {
		return nil, errors.New("control frame: complete.fileDigest missing")
	}
	return &Complete{Type: FrameComplete, FileDigest: *raw.FileDigest}, nil
}

func decodeFail(payload []byte) (ControlMsg, error) {
	var raw struct {
		Reason *string `json:"reason"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, errors.New("control frame: invalid fail")
	}
	if raw.Reason == nil {
		return nil, errors.New("control frame: fail.reason missing")
	}
	switch FailReason(*raw.Reason) {
	case FailDigestMismatch, FailIntegrity, FailSinkError, FailCanceled, FailQuota, FailRetryExhausted:
		return &Fail{Type: FrameFail, Reason: FailReason(*raw.Reason)}, nil
	default:
		return nil, fmt.Errorf("control frame: bad fail reason %q", *raw.Reason)
	}
}
