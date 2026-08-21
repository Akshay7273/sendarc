package wire

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Blinded LAN beacon constants (V15-PR04).
const (
	LanBeaconMagic   = "SB2B"
	LanBeaconVersion = 1

	LanBeaconHeaderSize = 32
	LanBeaconNonceSize  = 16
	LanBeaconTagSize    = 16
	MaxLanBeaconTags    = 32

	DomainLanBeaconTag = "sendbeam/2 lan-beacon:"

	DefaultLanBeaconEpochWindow = 15 * time.Minute
	DefaultLanBeaconMulticast   = "239.255.77.88:53317"
	DefaultLanBeaconPort        = 53317
)

var (
	// ErrInvalidLanBeacon indicates a corrupted or invalid LAN discovery beacon packet.
	ErrInvalidLanBeacon = errors.New("invalid LAN discovery beacon")
)

// LanBeacon represents a decoded privacy-preserving LAN discovery beacon.
type LanBeacon struct {
	Version     uint8
	Port        uint16
	Timestamp   time.Time
	BeaconNonce []byte   // 16 bytes
	Tags        [][]byte // Slice of 16-byte blinded tags
}

// DeriveLanBeaconTag derives a 16-byte truncated blinded tag for a paired device.
func DeriveLanBeaconTag(kPair, nonce []byte, epochIndex int64) []byte {
	epochStr := strconv.FormatInt(epochIndex, 10)
	mac := hmac.New(sha256.New, kPair)
	mac.Write([]byte(DomainLanBeaconTag))
	mac.Write(nonce)
	mac.Write([]byte(epochStr))
	full := mac.Sum(nil)
	tag := make([]byte, LanBeaconTagSize)
	copy(tag, full[:LanBeaconTagSize])
	return tag
}

// DeriveLanBeaconTagsForDevice computes candidate tags for [epoch-1, epoch, epoch+1].
func DeriveLanBeaconTagsForDevice(kPair, nonce []byte, t time.Time, window time.Duration) [][]byte {
	if window <= 0 {
		window = DefaultLanBeaconEpochWindow
	}
	epochIndex := t.UTC().Unix() / int64(window.Seconds())
	return [][]byte{
		DeriveLanBeaconTag(kPair, nonce, epochIndex-1),
		DeriveLanBeaconTag(kPair, nonce, epochIndex),
		DeriveLanBeaconTag(kPair, nonce, epochIndex+1),
	}
}

// NewLanBeacon constructs a LanBeacon with fresh nonce and blinded tags for the provided paired secrets.
func NewLanBeacon(port uint16, kPairs [][]byte, now time.Time, window time.Duration) (*LanBeacon, error) {
	if len(kPairs) > MaxLanBeaconTags {
		kPairs = kPairs[:MaxLanBeaconTags]
	}
	if window <= 0 {
		window = DefaultLanBeaconEpochWindow
	}

	nonce := make([]byte, LanBeaconNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate beacon nonce: %w", err)
	}

	epochIndex := now.UTC().Unix() / int64(window.Seconds())
	tags := make([][]byte, 0, len(kPairs))
	for _, kPair := range kPairs {
		if len(kPair) == 0 {
			continue
		}
		tag := DeriveLanBeaconTag(kPair, nonce, epochIndex)
		tags = append(tags, tag)
	}

	return &LanBeacon{
		Version:     LanBeaconVersion,
		Port:        port,
		Timestamp:   now.UTC().Truncate(time.Second),
		BeaconNonce: nonce,
		Tags:        tags,
	}, nil
}

// Encode serializes the LanBeacon into a binary datagram.
func (b *LanBeacon) Encode() ([]byte, error) {
	if b == nil || len(b.BeaconNonce) != LanBeaconNonceSize {
		return nil, ErrInvalidLanBeacon
	}
	if len(b.Tags) > MaxLanBeaconTags {
		return nil, ErrInvalidLanBeacon
	}

	totalLen := LanBeaconHeaderSize + (len(b.Tags) * LanBeaconTagSize)
	buf := make([]byte, totalLen)

	copy(buf[0:4], LanBeaconMagic)
	buf[4] = b.Version
	binary.BigEndian.PutUint16(buf[5:7], b.Port)
	binary.BigEndian.PutUint64(buf[7:15], uint64(b.Timestamp.Unix()))
	copy(buf[15:31], b.BeaconNonce)
	buf[31] = uint8(len(b.Tags))

	offset := LanBeaconHeaderSize
	for _, tag := range b.Tags {
		if len(tag) != LanBeaconTagSize {
			return nil, ErrInvalidLanBeacon
		}
		copy(buf[offset:offset+LanBeaconTagSize], tag)
		offset += LanBeaconTagSize
	}

	return buf, nil
}

// DecodeLanBeacon parses a raw binary datagram into a LanBeacon.
func DecodeLanBeacon(data []byte) (*LanBeacon, error) {
	if len(data) < LanBeaconHeaderSize {
		return nil, ErrInvalidLanBeacon
	}
	if string(data[0:4]) != LanBeaconMagic {
		return nil, ErrInvalidLanBeacon
	}
	ver := data[4]
	if ver != LanBeaconVersion {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidLanBeacon, ver)
	}

	port := binary.BigEndian.Uint16(data[5:7])
	tsSec := int64(binary.BigEndian.Uint64(data[7:15]))
	nonce := make([]byte, LanBeaconNonceSize)
	copy(nonce, data[15:31])
	tagCount := int(data[31])

	expectedLen := LanBeaconHeaderSize + (tagCount * LanBeaconTagSize)
	if len(data) != expectedLen {
		return nil, ErrInvalidLanBeacon
	}

	tags := make([][]byte, tagCount)
	offset := LanBeaconHeaderSize
	for i := 0; i < tagCount; i++ {
		tag := make([]byte, LanBeaconTagSize)
		copy(tag, data[offset:offset+LanBeaconTagSize])
		tags[i] = tag
		offset += LanBeaconTagSize
	}

	return &LanBeacon{
		Version:     ver,
		Port:        port,
		Timestamp:   time.Unix(tsSec, 0).UTC(),
		BeaconNonce: nonce,
		Tags:        tags,
	}, nil
}

// MatchLanBeacon checks which paired devices in localPairs match any tags in the beacon.
func MatchLanBeacon(b *LanBeacon, localPairs map[string][]byte, now time.Time, window time.Duration) []string {
	if b == nil || len(b.Tags) == 0 || len(localPairs) == 0 {
		return nil
	}
	if window <= 0 {
		window = DefaultLanBeaconEpochWindow
	}

	// Reject beacons with timestamp skewed more than 2 windows
	skew := now.Sub(b.Timestamp)
	if skew < 0 {
		skew = -skew
	}
	if skew > 2*window {
		return nil
	}

	var matched []string
	for devID, kPair := range localPairs {
		candidates := DeriveLanBeaconTagsForDevice(kPair, b.BeaconNonce, b.Timestamp, window)
		found := false
		for _, cand := range candidates {
			for _, advertised := range b.Tags {
				if subtle.ConstantTimeCompare(cand, advertised) == 1 {
					matched = append(matched, devID)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
	}
	return matched
}
