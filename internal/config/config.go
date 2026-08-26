// Package config owns reading and writing the ./chaosify/config file that ties the
// chaosify commands together. `init` produces it and `recon` consumes it, so
// both packages share this single source of truth for the on-disk location and
// format rather than each re-deriving it.
//
// Two load functions exist because the two phases disagree about a missing
// file: for init it is a normal first run (LoadOptional), for recon it is a
// hard error (LoadRequired).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aahan-pat/chaosify/internal/types"
)

const (
	// Path is the engagement file: written by `chaosify init` and read back by
	// `chaosify recon`. Both refer to this constant so the location is defined
	// once.
	Path string = "./.chaosclaw/config"

	indentSpaceCount int = 2
)

// LoadRequired reads the saved engagement and treats a missing file as an
// error. Use it from phases that cannot function without an onboarded
// engagement (e.g. recon): there is no connection to work with, so we refuse
// rather than guess. On success the returned pointer is always non-nil.
func LoadRequired() (*types.Config, error) {
	content, err := os.ReadFile(Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no engagement found at %s — run `chaosify init` first", Path)
	}
	if err != nil {
		return nil, fmt.Errorf("reading engagement config: %w", err)
	}

	cfg := &types.Config{}
	if err := json.Unmarshal(content, cfg); err != nil {
		return nil, fmt.Errorf("parsing engagement config: %w", err)
	}

	return cfg, nil
}

// LoadOptional reads the saved engagement but treats a missing file as a
// first run rather than an error, returning a fresh empty Config so the caller
// can proceed with defaults. Use it from phases that create the engagement
// (e.g. init). When err is nil the returned pointer is always usable and
// non-nil.
func LoadOptional() (*types.Config, error) {
	cfg := &types.Config{}

	content, err := os.ReadFile(Path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if err := json.Unmarshal(content, cfg); err != nil {
		return nil, fmt.Errorf("parsing profile: %w", err)
	}

	return cfg, nil
}

// Save writes cfg to Path, creating the .chaosclaw directory if needed. The
// file is written 0600 because it can describe a live engagement.
func Save(cfg *types.Config) error {
	if err := os.MkdirAll(filepath.Dir(Path), 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	f, err := os.OpenFile(Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("creating config file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", strings.Repeat(" ", indentSpaceCount))
	if err := enc.Encode(cfg); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	return nil
}
