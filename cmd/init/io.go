package initcmd

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
	configPath       string = "./.chaosclaw/config"
	indentSpaceCount int    = 2
)

// loadExistingConfig reads a previously saved engagement config from configPath.
// A missing file is not an error: it means this is a first run, so a fresh empty
// Config is returned with a nil error and the caller proceeds with defaults. The
// result is always a usable non-nil pointer when err is nil.
func loadExistingConfig() (*types.Config, error) {
	cfg := &types.Config{}

	content, err := os.ReadFile(configPath)
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

// dumpConfig stores config values in the .chaosclaw directory, creating it if
// needed. The file is written 0600 because it can describe a live engagement.
func dumpConfig(cfg *types.Config) error {
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
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
