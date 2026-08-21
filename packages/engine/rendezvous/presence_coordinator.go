// Package rendezvous provides room-based signaling and privacy-preserving opaque presence coordination.
package rendezvous

import (
	"context"
	"time"

	"github.com/sendbeam/engine/trust"
	"github.com/sendbeam/wire"
)

// PresenceCoordinator manages opaque handle calculation and inbound presence verification.
type PresenceCoordinator struct {
	store       trust.Store
	resolver    trust.SecretResolver
	epochWindow time.Duration
}

// NewPresenceCoordinator creates a new PresenceCoordinator.
func NewPresenceCoordinator(store trust.Store, resolver trust.SecretResolver, epochWindow time.Duration) *PresenceCoordinator {
	if epochWindow <= 0 {
		epochWindow = wire.DefaultRendezvousEpochWindow
	}
	return &PresenceCoordinator{
		store:       store,
		resolver:    resolver,
		epochWindow: epochWindow,
	}
}

// GetActiveHandles returns a mapping of DeviceID to candidate handles for all trusted paired devices.
func (c *PresenceCoordinator) GetActiveHandles(ctx context.Context, now time.Time) (map[string][]string, error) {
	devices, err := c.store.ListDevices(ctx)
	if err != nil {
		return nil, err
	}

	res := make(map[string][]string)
	for _, dev := range devices {
		if dev.Revoked {
			continue
		}
		kPair, err := c.resolver.ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err != nil || len(kPair) == 0 {
			continue
		}
		handles := wire.DeriveRendezvousHandlesWithSkew(kPair, now, c.epochWindow)
		res[dev.DeviceID] = handles
	}
	return res, nil
}

// MatchInboundPresence tests an incoming opaque handle and proof against stored paired devices.
func (c *PresenceCoordinator) MatchInboundPresence(ctx context.Context, handle string, nonce []byte, proof string, now time.Time) (string, bool) {
	if !wire.ValidateRendezvousHandle(handle) {
		return "", false
	}

	devices, err := c.store.ListDevices(ctx)
	if err != nil || len(devices) == 0 {
		return "", false
	}

	for _, dev := range devices {
		if dev.Revoked {
			continue
		}
		kPair, err := c.resolver.ResolvePairSecret(ctx, dev.DeviceID, dev.PairCredentialRef)
		if err != nil || len(kPair) == 0 {
			continue
		}

		if wire.MatchRendezvousHandle(kPair, handle, now, c.epochWindow) {
			if len(proof) > 0 && len(nonce) > 0 {
				if wire.VerifyPresenceProof(kPair, handle, nonce, proof) {
					return dev.DeviceID, true
				}
			} else {
				return dev.DeviceID, true
			}
		}
	}
	return "", false
}
