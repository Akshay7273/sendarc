package engine

import (
	"reflect"
	"testing"

	"github.com/sendbeam/engine/rendezvous"
)

// TestServiceInfo confirms the service reports a live runtime.
func TestServiceInfo(t *testing.T) {
	info := NewService().Info()
	if info.GoVersion == "" {
		t.Fatal("GoVersion empty")
	}
}

// TestServiceCaps confirms the service surfaces the engine's capability set by
// delegating to the engine (the shell must consume github.com/sendbeam/engine,
// not a copy — the import path alone guarantees the module, and equality with a
// direct engine call proves delegation).
func TestServiceCaps(t *testing.T) {
	caps := NewService().Caps()
	want := rendezvous.DefaultCaps()
	if !reflect.DeepEqual(caps, want) {
		t.Fatalf("service caps %+v != engine defaults %+v", caps, want)
	}
}

// TestServiceSelfCheck runs a complete in-process engine transfer (SPAKE2
// rendezvous, encrypted relay, durable receive, verification) through the
// service — no network, no display.
func TestServiceSelfCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("self-check runs a full engine transfer")
	}
	res := NewService().SelfCheck()
	if !res.OK {
		t.Fatalf("self-check failed: %s", res.Failure)
	}
	if res.Files != 1 || res.Bytes == 0 {
		t.Fatalf("self-check produced unexpected output: %+v", res)
	}
	if res.Phase != "verified" {
		t.Fatalf("self-check phase = %q, want verified", res.Phase)
	}
}
