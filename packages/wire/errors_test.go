package wire

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestErrorfCarriesCode(t *testing.T) {
	err := Errorf(CodeRelay, "relay switch timed out")
	if err.Error() != "relay switch timed out" {
		t.Fatalf("message = %q", err.Error())
	}
	if CodeOf(err) != CodeRelay {
		t.Fatalf("code = %s, want RELAY", CodeOf(err))
	}
}

func TestCodeOfWalksWrappedChain(t *testing.T) {
	inner := Errorf(CodeConnection, "signaling closed")
	wrapped := fmt.Errorf("transfer: %w", inner)
	if CodeOf(wrapped) != CodeConnection {
		t.Fatalf("code = %s, want CONNECTION", CodeOf(wrapped))
	}
}

func TestCodeOfUnclassifiedIsInternal(t *testing.T) {
	if CodeOf(errors.New("plain")) != CodeInternal {
		t.Fatalf("plain error code = %s, want INTERNAL", CodeOf(errors.New("plain")))
	}
}

func TestCodeOfContextCanceled(t *testing.T) {
	if CodeOf(context.Canceled) != CodeCanceled {
		t.Fatalf("context canceled code = %s, want CANCELED", CodeOf(context.Canceled))
	}
	if CodeOf(fmt.Errorf("wrapped: %w", context.Canceled)) != CodeCanceled {
		t.Fatalf("wrapped context canceled code = %s, want CANCELED", CodeOf(fmt.Errorf("wrapped: %w", context.Canceled)))
	}
}
