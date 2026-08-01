/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

// Package initcmd defines the `chaosify init` subcommand. It lives in its own
// package so the command wiring stays separate from the root command and from
// the domain packages under internal/. New() returns the fully configured
// *cobra.Command for the root command to attach.
//
// The file layout within the package:
//
//   - init.go    — the command definition (New) and the top-level runInit flow.
//   - collect.go — the per-field collectors that make up the two onboarding phases.
//   - helpers.go — client construction, the final summary, and flag accessors.
package initcmd

import (
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"

	"github.com/aahan-pat/chaosify/internal/types"
	"github.com/aahan-pat/chaosify/internal/ui"
)

// connectTimeout bounds every live API-server call made during onboarding.
const connectTimeout = 30 * time.Second

// clientset is a short local alias for the client-go clientset type, so the
// helper signatures below stay readable.
type clientset = kubernetes.Clientset

// New builds the init command. It walks the operator through the two-phase
// onboarding described in the engagement runbook: offline authorization +
// connection details first, then connected recon (identity, scope, cluster,
// stop-list, run mode).
//
// The command is written around one rule — "provided-else-prompt": every field
// checks its flag first (cmd.Flags().Changed) and only prompts when the flag was
// not set. That makes `chaosify init` (interactive) and a fully-flagged CI
// invocation the same code path.
func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Onboard a chaosify engagement (authorization, connection, scope)",
		Long: `init collects and validates everything chaosify needs before it will
touch a cluster: the authorization artifact and its date window (offline, a hard
gate), then the connection, identity, namespace scope, stop-list and run mode
(online). Any field can be supplied via a flag to run non-interactively.`,
		RunE: runInit,
	}

	f := cmd.Flags()
	// Phase 1 — offline.
	f.String("engagement-id", "", "Engagement identifier")
	f.String("sign-off-ref", "", "Sign-off / authorization document reference")
	f.String("valid-from", "", "Authorization window start (YYYY-MM-DD)")
	f.String("valid-until", "", "Authorization window end (YYYY-MM-DD)")
	f.String("kubeconfig", "", "Path to kubeconfig (default $KUBECONFIG or ~/.kube/config)")
	f.String("context", "", "Kubeconfig context to use")
	f.Bool("manual", false, "Enter connection details manually instead of a kubeconfig")
	f.String("endpoint", "", "API server endpoint (manual mode)")
	f.String("ca-cert", "", "CA certificate path (manual mode)")
	f.String("credential", "", "Bearer token (manual mode)")
	f.Bool("tls-skip-verify", false, "Skip TLS verification (manual mode; dangerous)")
	// Phase 2 — connected.
	f.StringSlice("namespaces", nil, "In-scope namespaces")
	f.StringSlice("denylist", nil, "Namespaces to exclude (stop list)")
	f.StringSlice("deny-rules", nil, "Finer resource/action deny rules")
	f.String("run-mode", string(types.RunModeDryRun), "Run mode: dry-run or active")
	f.String("expected-privilege", "", "Expected privilege level")

	return cmd
}

func runInit(cmd *cobra.Command, _ []string) error {
	// Seed cfg from a previously saved engagement, if any. A first run (no
	// .chaosclaw config) comes back as an empty config, not an error, so only a
	// real read/parse failure stops us here.
	cfg, err := loadExistingConfig()
	if err != nil {
		return err
	}

	// Changed reports whether a flag was explicitly set — the "provided" signal.
	changed := func(name string) bool { return cmd.Flags().Changed(name) }

	// Phase 1 — Offline (before connecting). Each step is a closure so the
	// differing signatures collapse into one uniform "step" that runSteps can
	// run in order, stopping at the first error.
	ui.PrintBanner("Phase 1 — Offline · Authorization & Connection")
	if err := runSteps(
		func() error { return collectAuthorization(cmd, changed, cfg) },
		func() error { return collectConnection(cmd, changed, cfg) },
	); err != nil {
		return err
	}

	// Phase 2 — Connected (requires live queries). buildClient sits between the
	// phases because every step below needs the client and host it produces.
	ui.PrintBanner("Phase 2 — Connected · Identity, Scope & Run Mode")
	clientset, host, err := buildClient(cfg)
	if err != nil {
		return err
	}
	if err := runSteps(
		func() error { return verifyIdentity(clientset, cfg) },
		func() error { return collectCluster(cfg, host) },
		func() error { return collectNamespaces(cmd, changed, clientset, cfg) },
		func() error { return collectDenylist(cmd, changed, cfg) },
		func() error { return collectRunMode(cmd, changed, cfg) },
		func() error { return collectExpectedPrivilege(cmd, changed, cfg) },
	); err != nil {
		return err
	}

	echoSummary(cfg)

	// Persist the resolved engagement so a later run can reload it.
	if err := dumpConfig(cfg); err != nil {
		return err
	}

	return nil
}
