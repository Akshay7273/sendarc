package wire

import (
	"strings"
	"testing"
)

func TestCompletionDigestInteropVector(t *testing.T) {
	a := strings.Repeat("a", 64)
	b := strings.Repeat("b", 64)
	if got := CompletionDigest([]FileEntry{{FileDigest: a}}); got != a {
		t.Fatalf("single completion digest = %s", got)
	}
	want := "5e9ae866add9a85d69c3481d059bb9f158a39e5670ba11f95112fc409630894e"
	if got := CompletionDigest([]FileEntry{{FileDigest: a}, {FileDigest: b}}); got != want {
		t.Fatalf("multi completion digest = %s, want %s", got, want)
	}
}
