// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package tokensource

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

const (
	firstToken  = "fake-sa-token-one"
	secondToken = "fake-sa-token-two"
)

// fakeClock is a settable clock so the refresh ceiling can be crossed
// without sleeping.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func writeToken(t *testing.T, path, token string, mtime time.Time) {
	t.Helper()
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("set token file mtime: %v", err)
	}
}

func newTestFile(t *testing.T, path string, clk *fakeClock, buf *bytes.Buffer) *File {
	t.Helper()
	f, err := newFile(path, zerolog.New(buf), clk.now)
	if err != nil {
		t.Fatalf("newFile: %v", err)
	}
	return f
}

func TestFileReadsTokenFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, firstToken+"\n", time.Unix(1000, 0))

	var buf bytes.Buffer
	f, err := NewFile(path, zerolog.New(&buf))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}

	if got := f.Token(); got != firstToken {
		t.Fatalf("Token() = %q, want %q", got, firstToken)
	}
}

func TestFilePicksUpRotatedFileOnMtimeChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	clk := &fakeClock{t: time.Unix(5000, 0)}
	var buf bytes.Buffer
	f := newTestFile(t, path, clk, &buf)

	writeToken(t, path, secondToken, time.Unix(2000, 0))
	clk.t = clk.t.Add(time.Second)

	if got := f.Token(); got != secondToken {
		t.Fatalf("Token() after rotation = %q, want %q", got, secondToken)
	}
}

func TestFileRefreshesAtLeastEverySixtySeconds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	mtime := time.Unix(1000, 0)
	writeToken(t, path, firstToken, mtime)
	clk := &fakeClock{t: time.Unix(5000, 0)}
	var buf bytes.Buffer
	f := newTestFile(t, path, clk, &buf)

	// Same mtime, new content: only the refresh ceiling can surface it.
	writeToken(t, path, secondToken, mtime)

	clk.t = clk.t.Add(59 * time.Second)
	if got := f.Token(); got != firstToken {
		t.Fatalf("Token() before 60s = %q, want cached %q", got, firstToken)
	}

	clk.t = clk.t.Add(time.Second)
	if got := f.Token(); got != secondToken {
		t.Fatalf("Token() at 60s = %q, want %q", got, secondToken)
	}
}

func TestFileKeepsLastGoodTokenWhenReloadFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	clk := &fakeClock{t: time.Unix(5000, 0)}
	var buf bytes.Buffer
	f := newTestFile(t, path, clk, &buf)

	writeToken(t, path, "", time.Unix(2000, 0))
	clk.t = clk.t.Add(time.Second)

	if got := f.Token(); got != firstToken {
		t.Fatalf("Token() after empty reload = %q, want last good %q", got, firstToken)
	}
}

func TestNewFileMissingFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent")

	var buf bytes.Buffer
	if _, err := NewFile(path, zerolog.New(&buf)); err == nil {
		t.Fatal("NewFile on a missing file: want error, got nil")
	}
	if !strings.Contains(buf.String(), path) {
		t.Fatalf("startup failure log should name the path; got %q", buf.String())
	}
}

func TestNewFileEmptyFileIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, " \n", time.Unix(1000, 0))

	var buf bytes.Buffer
	if _, err := NewFile(path, zerolog.New(&buf)); err == nil {
		t.Fatal("NewFile on an empty file: want error, got nil")
	}
	if !strings.Contains(buf.String(), path) {
		t.Fatalf("startup failure log should name the path; got %q", buf.String())
	}
}

func TestFileNeverLogsToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	clk := &fakeClock{t: time.Unix(5000, 0)}
	var buf bytes.Buffer
	f := newTestFile(t, path, clk, &buf)
	_ = f.Token()

	writeToken(t, path, secondToken, time.Unix(2000, 0))
	clk.t = clk.t.Add(time.Second)
	_ = f.Token()

	writeToken(t, path, "", time.Unix(3000, 0))
	clk.t = clk.t.Add(time.Second)
	_ = f.Token()

	out := buf.String()
	if !strings.Contains(out, path) {
		t.Fatalf("logs should name the token path; got %q", out)
	}
	if !strings.Contains(out, "reloaded") {
		t.Fatalf("logs should record the reload; got %q", out)
	}
	for _, tok := range []string{firstToken, secondToken} {
		if strings.Contains(out, tok) {
			t.Fatalf("logs leaked token %q: %q", tok, out)
		}
	}
}

func TestFromEnvUsesTokenFileWhenSet(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, dir)
	t.Setenv(EnvTokenFile, path)
	t.Setenv(EnvDevToken, "ignored-dev-token")

	var buf bytes.Buffer
	src, err := FromEnv(zerolog.New(&buf))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if got := src.Token(); got != firstToken {
		t.Fatalf("Token() = %q, want %q", got, firstToken)
	}
}

func TestFromEnvTokenFileMissingIsAnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvTokenDir, dir)
	t.Setenv(EnvTokenFile, filepath.Join(dir, "absent"))

	var buf bytes.Buffer
	if _, err := FromEnv(zerolog.New(&buf)); err == nil {
		t.Fatal("FromEnv with a missing token file: want error, got nil")
	}
}

func TestFromEnvDevTokenUnchangedWhenFileUnset(t *testing.T) {
	t.Setenv(EnvTokenFile, "")
	t.Setenv(EnvDevToken, "custom-dev-token")

	var buf bytes.Buffer
	src, err := FromEnv(zerolog.New(&buf))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if got := src.Token(); got != "custom-dev-token" {
		t.Fatalf("Token() = %q, want custom-dev-token", got)
	}
}

func TestFromEnvDevTokenDefaultWhenBothUnset(t *testing.T) {
	t.Setenv(EnvTokenFile, "")
	t.Setenv(EnvDevToken, "")

	var buf bytes.Buffer
	src, err := FromEnv(zerolog.New(&buf))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if got := src.Token(); got != "dev-connector-token" {
		t.Fatalf("Token() = %q, want dev-connector-token", got)
	}
}

func TestNewFileRefusesRelativePath(t *testing.T) {
	t.Chdir(t.TempDir())
	writeToken(t, "token", firstToken, time.Unix(1000, 0))

	var buf bytes.Buffer
	if _, err := NewFile("token", zerolog.New(&buf)); err == nil {
		t.Fatal("NewFile on a relative path: want error, got nil")
	}
}

func TestNewFileRefusesUncleanPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))

	for _, p := range []string{
		dir + "/sub/../token",
		dir + "//token",
		dir + "/./token",
	} {
		var buf bytes.Buffer
		if _, err := NewFile(p, zerolog.New(&buf)); err == nil {
			t.Fatalf("NewFile(%q): want error, got nil", p)
		}
	}
}

func TestFromEnvRefusesRelativeTokenFile(t *testing.T) {
	t.Setenv(EnvTokenDir, "")
	t.Setenv(EnvTokenFile, "tokens/token")

	var buf bytes.Buffer
	_, err := FromEnv(zerolog.New(&buf))
	if err == nil {
		t.Fatal("FromEnv with a relative token file: want error, got nil")
	}
	if !strings.Contains(err.Error(), EnvTokenFile) {
		t.Fatalf("error should name %s; got %q", EnvTokenFile, err)
	}
	if !strings.Contains(buf.String(), EnvTokenFile) {
		t.Fatalf("startup failure log should name %s; got %q", EnvTokenFile, buf.String())
	}
}

func TestFromEnvRefusesDotDotTokenFile(t *testing.T) {
	dir := t.TempDir()
	writeToken(t, filepath.Join(dir, "token"), firstToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, filepath.Join(dir, "tokens"))
	t.Setenv(EnvTokenFile, dir+"/tokens/../token")

	var buf bytes.Buffer
	_, err := FromEnv(zerolog.New(&buf))
	if err == nil {
		t.Fatal("FromEnv with a .. token file: want error, got nil")
	}
	if !strings.Contains(err.Error(), EnvTokenFile) {
		t.Fatalf("error should name %s; got %q", EnvTokenFile, err)
	}
}

func TestFromEnvRefusesTokenFileOutsideDefaultDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, "")
	t.Setenv(EnvTokenFile, path)

	var buf bytes.Buffer
	_, err := FromEnv(zerolog.New(&buf))
	if err == nil {
		t.Fatalf("FromEnv with a token file outside %s: want error, got nil", DefaultTokenDir)
	}
	if !strings.Contains(err.Error(), EnvTokenFile) {
		t.Fatalf("error should name %s; got %q", EnvTokenFile, err)
	}
	if strings.Contains(buf.String(), firstToken) || strings.Contains(err.Error(), firstToken) {
		t.Fatal("rejection leaked the token")
	}
}

func TestFromEnvRefusesTokenFileOutsideOverrideDir(t *testing.T) {
	root := t.TempDir()
	allowed := filepath.Join(root, "allowed")
	other := filepath.Join(root, "allowed-not")
	for _, d := range []string{allowed, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	path := filepath.Join(other, "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, allowed)
	t.Setenv(EnvTokenFile, path)

	var buf bytes.Buffer
	if _, err := FromEnv(zerolog.New(&buf)); err == nil {
		t.Fatal("FromEnv with a token file in a sibling of the allowed dir: want error, got nil")
	}
}

func TestFromEnvTokenDirOverrideAllowsFileUnderIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tokens", "token")
	if err := os.Mkdir(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, dir+"/")
	t.Setenv(EnvTokenFile, path)

	var buf bytes.Buffer
	src, err := FromEnv(zerolog.New(&buf))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if got := src.Token(); got != firstToken {
		t.Fatalf("Token() = %q, want %q", got, firstToken)
	}
}

func TestFromEnvRefusesRelativeTokenDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, "tokens")
	t.Setenv(EnvTokenFile, path)

	var buf bytes.Buffer
	_, err := FromEnv(zerolog.New(&buf))
	if err == nil {
		t.Fatal("FromEnv with a relative token dir: want error, got nil")
	}
	if !strings.Contains(err.Error(), EnvTokenDir) {
		t.Fatalf("error should name %s; got %q", EnvTokenDir, err)
	}
}

func TestCheckTokenPathAcceptsFileUnderDefaultDir(t *testing.T) {
	if err := checkTokenPath("/var/run/secrets/tokens/token", DefaultTokenDir); err != nil {
		t.Fatalf("checkTokenPath: %v", err)
	}
}

func TestFromEnvUsesWorkloadTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	writeToken(t, path, firstToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, dir)
	t.Setenv(EnvWorkloadTokenFile, path)
	t.Setenv(EnvTokenFile, "")
	t.Setenv(EnvDevToken, "ignored-dev-token")

	var buf bytes.Buffer
	src, err := FromEnv(zerolog.New(&buf))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if got := src.Token(); got != firstToken {
		t.Fatalf("Token() = %q, want %q", got, firstToken)
	}
}

func TestFromEnvPrefersWorkloadTokenFileOverAlias(t *testing.T) {
	dir := t.TempDir()
	workload, alias := filepath.Join(dir, "workload"), filepath.Join(dir, "alias")
	writeToken(t, workload, firstToken, time.Unix(1000, 0))
	writeToken(t, alias, secondToken, time.Unix(1000, 0))
	t.Setenv(EnvTokenDir, dir)
	t.Setenv(EnvWorkloadTokenFile, workload)
	t.Setenv(EnvTokenFile, alias)

	var buf bytes.Buffer
	src, err := FromEnv(zerolog.New(&buf))
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if got := src.Token(); got != firstToken {
		t.Fatalf("Token() = %q, want %q (the %s file)", got, firstToken, EnvWorkloadTokenFile)
	}
}
