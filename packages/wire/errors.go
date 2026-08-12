// Package wire errors: stable machine-readable error classes shared with the
// TypeScript protocol (see ADR 0002). Every externally visible error carries a
// class code plus a human message.
package wire

import (
	"context"
	"errors"
	"fmt"
)

// ErrorCode is a stable machine-readable error class (ADR 0002).
type ErrorCode string

// Stable machine-readable error class codes (ADR 0002).
const (
	CodeAuth          ErrorCode = "AUTH"
	CodeProtocol      ErrorCode = "PROTOCOL"
	CodeConnection    ErrorCode = "CONNECTION"
	CodeRelay         ErrorCode = "RELAY"
	CodeRetryExhausted ErrorCode = "RETRY_EXHAUSTED"
	CodeCanceled      ErrorCode = "CANCELED"
	CodeStorage       ErrorCode = "STORAGE"
	CodeSourceIO      ErrorCode = "SOURCE_IO"
	CodeDestIO        ErrorCode = "DEST_IO"
	CodeCompat        ErrorCode = "COMPAT"
	CodeInternal      ErrorCode = "INTERNAL"
)

// Error is an error carrying a stable machine-readable class.
type Error struct {
	Code ErrorCode
	msg  string
}

func (e *Error) Error() string { return e.msg }

// Errorf builds a classified error with a formatted message.
func Errorf(code ErrorCode, format string, args ...any) error {
	return &Error{Code: code, msg: fmt.Sprintf(format, args...)}
}

// CodeOf walks the error chain and returns the first classification found;
// unclassified errors are INTERNAL, and context cancellation is CANCELED.
func CodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if errors.Is(err, context.Canceled) {
		return CodeCanceled
	}
	return CodeInternal
}
