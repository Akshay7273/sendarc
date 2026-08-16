package engine

import (
	"github.com/wailsapp/wails/v3/pkg/application"
)

// PickResult is a native picker outcome. Error is set when the dialog is
// unavailable (server mode) or the user cancels.
type PickResult struct {
	Paths []string `json:"paths"`
	Error string   `json:"error,omitempty"`
}

// PickFiles opens the native multi-select picker for files and folders to send.
// In server mode (no GUI) it returns a descriptive error so the frontend can
// fall back to manual path entry.
func (s *TransferService) PickFiles() PickResult {
	app := application.Get()
	if app == nil || app.Dialog == nil {
		return PickResult{Error: "native dialogs unavailable (server mode); enter paths manually"}
	}
	dlg := app.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
		CanChooseFiles:          true,
		CanChooseDirectories:    true,
		AllowsMultipleSelection: true,
		Title:                   "Select files and folders to send",
		Message:                 "Choose one or more files or folders to send securely.",
		ButtonText:              "Select",
	})
	paths, err := dlg.PromptForMultipleSelection()
	if err != nil {
		return PickResult{Error: err.Error()}
	}
	return PickResult{Paths: paths}
}

// PickDestination opens a native folder picker for the receive destination.
// In server mode it returns a descriptive error.
func (s *TransferService) PickDestination() PickResult {
	app := application.Get()
	if app == nil || app.Dialog == nil {
		return PickResult{Error: "native dialogs unavailable (server mode); enter a destination path manually"}
	}
	dlg := app.Dialog.OpenFileWithOptions(&application.OpenFileDialogOptions{
		CanChooseFiles:       false,
		CanChooseDirectories: true,
		Title:                "Choose where to save received files",
		Message:              "Received files are written into this folder.",
		ButtonText:           "Choose",
	})
	dir, err := dlg.PromptForSingleSelection()
	if err != nil {
		return PickResult{Error: err.Error()}
	}
	if dir == "" {
		return PickResult{Error: "no destination selected"}
	}
	return PickResult{Paths: []string{dir}}
}
