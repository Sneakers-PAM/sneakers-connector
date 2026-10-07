// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package tokensource supplies the worker-identity token the connector
// puts in the identity field of every claim, reveal and report call. The
// token comes either from a file (a Kubernetes projected ServiceAccount token
// the kubelet rotates in place) or, when no file is configured, from the
// static dev token.
package tokensource

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	workloadauth "github.com/Bugs5382/go-workload-identity"
	"github.com/rs/zerolog"
)

const (
	// EnvWorkloadTokenFile names the env var holding the workload token file
	// path, the same file sent as the bearer token on every vault call. When
	// set, it takes precedence over EnvTokenFile and EnvDevToken.
	EnvWorkloadTokenFile = workloadauth.EnvTokenFile
	// EnvTokenFile is the older name for EnvWorkloadTokenFile, read when it
	// is unset. When set, it takes precedence over EnvDevToken.
	EnvTokenFile = "CONNECTOR_TOKEN_FILE" // #nosec G101 -- an env var name, not a credential
	// EnvDevToken names the env var holding the static dev token.
	EnvDevToken = "CONNECTOR_DEV_TOKEN" // #nosec G101 -- an env var name, not a credential
	// EnvTokenDir names the env var holding the directory the token file
	// must sit under. Defaults to DefaultTokenDir.
	EnvTokenDir = "CONNECTOR_TOKEN_DIR"
	// DefaultTokenDir is the Kubernetes convention for mounted tokens.
	DefaultTokenDir = "/var/run/secrets/" // #nosec G101 -- a directory path, not a credential

	defaultDevToken = "dev-connector-token" // #nosec G101 -- the public dev token, refused by the vault in production

	// maxRefresh caps how long a cached token is trusted when the file's
	// mtime has not moved, in case a rotation lands without an mtime change.
	maxRefresh = 60 * time.Second
)

// Source returns the token to present to the vault right now.
type Source interface {
	Token() string
}

// Static is a fixed token.
type Static string

// Token returns the fixed token.
func (s Static) Token() string { return string(s) }

// File serves a token read from a file, re-reading it when the file's mtime
// changes or maxRefresh has passed since the last read. A failed or empty
// re-read keeps the last good token, so a transient kubelet swap never
// blanks the identity.
type File struct {
	path   string
	logger zerolog.Logger
	now    func() time.Time

	mu       sync.Mutex
	token    string
	mtime    time.Time
	loadedAt time.Time
}

// NewFile reads the token at path, which must be absolute and already in
// clean form. A missing, unreadable or empty file is an error, since the
// connector can't authenticate without it.
func NewFile(path string, logger zerolog.Logger) (*File, error) {
	return newFile(path, logger, time.Now)
}

func newFile(path string, logger zerolog.Logger, now func() time.Time) (*File, error) {
	if err := checkCleanAbs(path); err != nil {
		logger.Error().Err(err).Msg("connector token file path rejected")
		return nil, err
	}
	path = filepath.Clean(path)
	f := &File{
		path:   path,
		logger: logger.With().Str("token_file", path).Logger(),
		now:    now,
	}
	info, err := os.Stat(path) // #nosec G703 -- path checked clean and absolute above, and confined to the token directory by FromEnv
	if err != nil {
		f.logger.Error().Err(err).Msg("connector token file unavailable")
		return nil, fmt.Errorf("connector token file %s: %w", path, err)
	}
	if err := f.load(info.ModTime(), now()); err != nil {
		f.logger.Error().Err(err).Msg("connector token file unusable")
		return nil, err
	}
	f.logger.Info().Time("mtime", f.mtime).Msg("connector token loaded")
	return f, nil
}

// Token returns the current token, reloading it first if it may be stale.
func (f *File) Token() string {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := f.now()
	info, err := os.Stat(f.path)
	if err != nil {
		f.logger.Warn().Err(err).Msg("connector token file stat failed; keeping last good token")
		return f.token
	}

	reason := ""
	switch {
	case !info.ModTime().Equal(f.mtime):
		reason = "mtime changed"
	case now.Sub(f.loadedAt) >= maxRefresh:
		reason = "refresh interval"
	default:
		return f.token
	}

	if err := f.load(info.ModTime(), now); err != nil {
		f.logger.Warn().Err(err).Str("reason", reason).Msg("connector token reload failed; keeping last good token")
		return f.token
	}
	f.logger.Info().Str("reason", reason).Time("mtime", f.mtime).Msg("connector token reloaded")
	return f.token
}

func (f *File) load(mtime, now time.Time) error {
	raw, err := os.ReadFile(f.path)
	if err != nil {
		return fmt.Errorf("read connector token file %s: %w", f.path, err)
	}
	tok := strings.TrimSpace(string(raw))
	if tok == "" {
		return fmt.Errorf("connector token file %s is empty", f.path)
	}
	f.token = tok
	f.mtime = mtime
	f.loadedAt = now
	return nil
}

// checkCleanAbs refuses a relative path or one filepath.Clean would change
// (".." or "." segments, doubled or trailing separators). Callers still open
// the filepath.Clean result so gosec's taint analysis sees the sanitizer.
func checkCleanAbs(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("connector token file path %q must be absolute", path)
	}
	if cleaned := filepath.Clean(path); cleaned != path {
		return fmt.Errorf("connector token file path %q is not in clean form (%q)", path, cleaned)
	}
	return nil
}

// checkTokenPath refuses path unless it is absolute, already clean and
// strictly under the absolute directory base.
func checkTokenPath(path, base string) error {
	if err := checkCleanAbs(path); err != nil {
		return err
	}
	rel, err := filepath.Rel(filepath.Clean(base), path)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return fmt.Errorf("connector token file path %q is not under %q", path, base)
	}
	return nil
}

// FromEnv picks the token source from the environment: the file named by
// EnvWorkloadTokenFile or, when that is unset, EnvTokenFile; otherwise the
// static EnvDevToken (default "dev-connector-token"). The token file must be
// an absolute, clean path under EnvTokenDir (default DefaultTokenDir).
func FromEnv(logger zerolog.Logger) (Source, error) {
	fileEnv := EnvWorkloadTokenFile
	raw := os.Getenv(fileEnv)
	if raw == "" {
		fileEnv = EnvTokenFile
		raw = os.Getenv(fileEnv)
	}
	if raw != "" {
		base := os.Getenv(EnvTokenDir)
		if base == "" {
			base = DefaultTokenDir
		}
		if !filepath.IsAbs(base) {
			err := fmt.Errorf("%s %q must be an absolute directory", EnvTokenDir, base)
			logger.Error().Err(err).Str("env", EnvTokenDir).Msg("connector token dir rejected")
			return nil, err
		}
		if err := checkTokenPath(raw, base); err != nil {
			err = fmt.Errorf("%s: %w", fileEnv, err)
			logger.Error().Err(err).Str("env", fileEnv).Str("token_dir", base).Msg("connector token file path rejected")
			return nil, err
		}
		return NewFile(filepath.Clean(raw), logger)
	}
	tok := os.Getenv(EnvDevToken)
	if tok == "" {
		tok = defaultDevToken
	}
	logger.Info().Msg("connector token from " + EnvDevToken + " (no " + EnvWorkloadTokenFile + " or " + EnvTokenFile + " set)")
	return Static(tok), nil
}
