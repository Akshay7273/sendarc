package engine

// Picker defines the native dialog interface for selecting files or folders.
type Picker interface {
	PickFiles() ([]string, error)
	PickDestination() (string, error)
}

// PickResult is a native picker outcome. Error is set when the dialog is
// unavailable (server mode) or the user cancels.
type PickResult struct {
	Paths []string `json:"paths"`
	Error string   `json:"error,omitempty"`
}

// PickFiles opens the native multi-select picker for files and folders to send.
// In server mode (no GUI or nil picker) it returns a descriptive error so the frontend can
// fall back to manual path entry.
func (s *TransferService) PickFiles() PickResult {
	s.mu.Lock()
	picker := s.picker
	s.mu.Unlock()

	if picker == nil {
		return PickResult{Error: "native dialogs unavailable (server mode); enter paths manually"}
	}
	paths, err := picker.PickFiles()
	if err != nil {
		return PickResult{Error: err.Error()}
	}
	return PickResult{Paths: paths}
}

// PickDestination opens a native folder picker for the receive destination.
// In server mode it returns a descriptive error.
func (s *TransferService) PickDestination() PickResult {
	s.mu.Lock()
	picker := s.picker
	s.mu.Unlock()

	if picker == nil {
		return PickResult{Error: "native dialogs unavailable (server mode); enter a destination path manually"}
	}
	dir, err := picker.PickDestination()
	if err != nil {
		return PickResult{Error: err.Error()}
	}
	if dir == "" {
		return PickResult{Error: "no destination selected"}
	}
	return PickResult{Paths: []string{dir}}
}
