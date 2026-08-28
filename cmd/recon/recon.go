/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

// Package reconcmd defines the `chaosify recon` command group. recon is the
// read-only reconnaissance phase of an engagement: it inspects the target
// cluster through the identity established during `chaosify init` and never
// mutates state.
//
// The group is a bare parent command with one child per recon probe, e.g.
//
//	chaosify recon permissions
//
// Each subcommand lives in its own file but shares this package's helpers
// (loadEngagement, buildClient) so every probe resolves the same saved
// engagement and connects the same way. New() returns the fully wired parent
// for the root command to attach.
package reconcmd

import (
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"

	getcmd "github.com/aahan-pat/chaosify/cmd/recon/get"
	"github.com/aahan-pat/chaosify/internal/config"
	"github.com/aahan-pat/chaosify/internal/kube"
	"github.com/aahan-pat/chaosify/internal/types"
)

// reconTimeout bounds every live API-server call made during recon.
const reconTimeout = 30 * time.Second

// New builds the recon parent command and attaches its subcommands. The parent
// carries no RunE of its own: running `chaosify recon` with no subcommand prints
// help, which cobra does by default when RunE is nil.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "recon",
		Short: "Read-only reconnaissance of the target cluster",
		Long: `recon runs the passive, read-only probes chaosify uses to understand a
cluster before any active testing. Every subcommand operates as the identity
resolved during init and only reads — it never mutates cluster state.`,
	}

	// get lives in its own package; it takes a connector rather than reaching
	// back into reconcmd. permissions is attached here (not inside get.New) so
	// the get package need not import this one — that would be a cycle.
	get := getcmd.New(connect)
	get.AddCommand(newPermissionsCmd())
	cmd.AddCommand(get)

	return cmd
}

// loadEngagement reads the engagement saved by `chaosify init`. A recon probe is
// meaningless without one, so unlike init a missing config is a hard error here
// rather than a fresh-start signal.
func loadEngagement() (*types.Config, error) {
	return config.LoadRequired()
}

// buildClient constructs the clientset from whichever connection source the
// saved engagement recorded, mirroring init's own client construction.
func buildClient(cfg *types.Config) (*kubernetes.Clientset, string, error) {
	if cfg.Connection.Manual {
		return kube.ClientFromManual(cfg.Connection)
	}
	return kube.ClientFromContext(cfg.Connection.KubeconfigPath, cfg.Connection.ContextName)
}

// connect loads the saved engagement and opens a live client for it — the setup
// every recon probe repeats. It returns both so callers can read the config's
// scope (namespaces, identity) alongside the client. Shared package-wide, so any
// subcommand file can call it.
func connect() (*kubernetes.Clientset, *types.Config, error) {
	cfg, err := loadEngagement()
	if err != nil {
		return nil, nil, err
	}
	client, _, err := buildClient(cfg)
	if err != nil {
		return nil, nil, err
	}
	return client, cfg, nil
}
