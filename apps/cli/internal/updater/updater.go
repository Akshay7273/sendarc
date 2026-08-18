package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	// ErrNoUpdateAvailable is returned when already running the latest or newer version.
	ErrNoUpdateAvailable = errors.New("no update available")

	// ErrDevVersionNoUpdate is returned when running a development build without force.
	ErrDevVersionNoUpdate = errors.New("running development build (updates require tagged release or --force)")

	// ErrChannelMismatch is returned when a release is incompatible with the selected channel.
	ErrChannelMismatch = errors.New("latest release is not compatible with current update channel")
)

// CheckResult represents the outcome of an update check.
type CheckResult struct {
	CurrentVersion  Version       `json:"current_version"`
	LatestVersion   Version       `json:"latest_version"`
	Channel         Channel       `json:"channel"`
	UpdateAvailable bool          `json:"update_available"`
	TargetAsset     *ReleaseAsset `json:"target_asset,omitempty"`
	ReleaseNotes    string        `json:"release_notes,omitempty"`
	PublishedAt     time.Time     `json:"published_at,omitempty"`
	Message         string        `json:"message"`
}

// Updater coordinates checking, downloading, and applying updates.
type Updater struct {
	CurrentVersion Version
	Channel        Channel
	Repository     string
	BaseURL        string // Default https://api.github.com
	HTTPClient     *http.Client
	TargetOS       string
	TargetArch     string
	ExecutablePath string

	mu sync.Mutex
}

// Option configures an Updater.
type Option func(*Updater)

// WithChannel sets the updater channel.
func WithChannel(ch Channel) Option {
	return func(u *Updater) {
		u.Channel = ch
	}
}

// WithBaseURL overrides the release endpoint base URL (useful for testing and mirrors).
func WithBaseURL(rawURL string) Option {
	return func(u *Updater) {
		u.BaseURL = rawURL
	}
}

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(client *http.Client) Option {
	return func(u *Updater) {
		u.HTTPClient = client
	}
}

// WithExecutablePath overrides the target binary path.
func WithExecutablePath(p string) Option {
	return func(u *Updater) {
		u.ExecutablePath = p
	}
}

// WithTargetPlatform sets the OS and architecture.
func WithTargetPlatform(targetOS, targetArch string) Option {
	return func(u *Updater) {
		u.TargetOS = targetOS
		u.TargetArch = targetArch
	}
}

// New creates a new Updater instance.
func New(currentVerStr string, repo string, opts ...Option) (*Updater, error) {
	ver, err := ParseVersion(currentVerStr)
	if err != nil {
		return nil, fmt.Errorf("parsing current version %q: %w", currentVerStr, err)
	}

	execPath, _ := os.Executable()
	if execPath != "" {
		execPath, _ = filepath.EvalSymlinks(execPath)
	}

	u := &Updater{
		CurrentVersion: ver,
		Channel:        ChannelStable,
		Repository:     repo,
		BaseURL:        "https://api.github.com",
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		TargetOS:       runtime.GOOS,
		TargetArch:     runtime.GOARCH,
		ExecutablePath: execPath,
	}

	for _, opt := range opts {
		opt(u)
	}

	return u, nil
}

// Check checks for available updates against the configured channel.
func (u *Updater) Check(ctx context.Context) (*CheckResult, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	res := &CheckResult{
		CurrentVersion: u.CurrentVersion,
		Channel:        u.Channel,
	}

	if u.CurrentVersion.IsDev {
		res.Message = fmt.Sprintf("Running development build (%s). Channel: %s.", u.CurrentVersion.String(), u.Channel)
		return res, nil
	}

	// Fetch releases
	releases, err := u.fetchReleases(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching release information: %w", err)
	}

	if len(releases) == 0 {
		res.Message = "No releases found."
		return res, nil
	}

	// Select the highest eligible release matching channel policy
	var candidate *ReleaseMetadata
	for i := range releases {
		rel := &releases[i]
		if !rel.Version.CompatibleWithChannel(u.Channel) {
			continue
		}
		if candidate == nil || rel.Version.IsGreaterThan(candidate.Version) {
			candidate = rel
		}
	}

	if candidate == nil {
		res.Message = fmt.Sprintf("No releases found matching channel %q.", u.Channel)
		return res, nil
	}

	res.LatestVersion = candidate.Version
	res.PublishedAt = candidate.PublishedAt
	res.ReleaseNotes = candidate.ReleaseNotes

	if !candidate.Version.IsGreaterThan(u.CurrentVersion) {
		res.UpdateAvailable = false
		res.Message = fmt.Sprintf("SendBeam is up to date (version %s on channel %s).", u.CurrentVersion, u.Channel)
		return res, nil
	}

	// Find matching target platform asset
	asset, err := candidate.FindTargetAsset(u.TargetOS, u.TargetArch)
	if err != nil {
		return nil, fmt.Errorf("checking update asset: %w", err)
	}

	res.UpdateAvailable = true
	res.TargetAsset = asset
	res.Message = fmt.Sprintf("Update available: %s → %s (%s)", u.CurrentVersion, candidate.Version, u.Channel)

	return res, nil
}

// Apply downloads and atomically replaces the active executable with the new version.
func (u *Updater) Apply(ctx context.Context, check *CheckResult) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	if check == nil || !check.UpdateAvailable || check.TargetAsset == nil {
		return ErrNoUpdateAvailable
	}

	if u.ExecutablePath == "" {
		return errors.New("cannot determine active executable path for replacement")
	}

	// Download asset stream
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, check.TargetAsset.DownloadURL, nil)
	if err != nil {
		return fmt.Errorf("preparing download request: %w", err)
	}
	req.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading update artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("update download failed with HTTP %d %s", resp.StatusCode, resp.Status)
	}

	// Apply atomic update with verified checksum
	applyOpts := ApplyOptions{
		TargetPath:     u.ExecutablePath,
		TargetOS:       u.TargetOS,
		ExpectedSHA256: check.TargetAsset.SHA256,
		ArchiveName:    check.TargetAsset.Name,
	}

	if err := ApplyUpdate(ctx, resp.Body, applyOpts); err != nil {
		return fmt.Errorf("applying update: %w", err)
	}

	return nil
}

// fetchReleases queries releases from the repository.
func (u *Updater) fetchReleases(ctx context.Context) ([]ReleaseMetadata, error) {
	relURL := fmt.Sprintf("%s/repos/%s/releases", strings.TrimSuffix(u.BaseURL, "/"), u.Repository)
	if !strings.HasPrefix(relURL, "http://") && !strings.HasPrefix(relURL, "https://") {
		return nil, fmt.Errorf("invalid base URL %q", u.BaseURL)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, relURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("HTTP %d fetching releases: %s", resp.StatusCode, string(body))
	}

	var ghReleases []struct {
		TagName      string    `json:"tag_name"`
		Prerelease   bool      `json:"prerelease"`
		PublishedAt  time.Time `json:"published_at"`
		Body         string    `json:"body"`
		Assets       []struct {
			Name               string `json:"name"`
			Size               int64  `json:"size"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghReleases); err != nil {
		return nil, fmt.Errorf("decoding releases JSON: %w", err)
	}

	results := make([]ReleaseMetadata, 0, len(ghReleases))
	for _, gh := range ghReleases {
		ver, err := ParseVersion(gh.TagName)
		if err != nil {
			continue // skip unparseable tags
		}

		assets := make([]ReleaseAsset, 0, len(gh.Assets))
		var checksumURL string
		for _, a := range gh.Assets {
			assets = append(assets, ReleaseAsset{
				Name:        a.Name,
				Size:        a.Size,
				DownloadURL: a.BrowserDownloadURL,
			})
			if a.Name == "SHA256SUMS.txt" {
				checksumURL = a.BrowserDownloadURL
			}
		}

		meta := ReleaseMetadata{
			Version:      ver,
			TagName:      gh.TagName,
			Prerelease:   gh.Prerelease,
			PublishedAt:  gh.PublishedAt,
			ReleaseNotes: gh.Body,
			Assets:       assets,
		}

		// If SHA256SUMS.txt exists, fetch and parse it
		if checksumURL != "" {
			if checksums, err := u.fetchChecksums(ctx, checksumURL); err == nil {
				meta.Checksums = checksums
				for i := range meta.Assets {
					if hash, ok := checksums[meta.Assets[i].Name]; ok {
						meta.Assets[i].SHA256 = hash
					}
				}
			}
		}

		results = append(results, meta)
	}

	return results, nil
}

func (u *Updater) fetchChecksums(ctx context.Context, checksumURL string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SendBeam-Updater/"+u.CurrentVersion.String())

	resp, err := u.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d fetching checksums", resp.StatusCode)
	}

	return ParseChecksums(resp.Body)
}

// IsValidUpdateURL checks that an update endpoint uses HTTPS in production.
func IsValidUpdateURL(rawURL string, allowInsecure bool) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if allowInsecure && (parsed.Scheme == "http" && (parsed.Hostname() == "localhost" || parsed.Hostname() == "127.0.0.1")) {
		return true
	}
	return false
}
