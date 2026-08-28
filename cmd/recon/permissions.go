/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

package reconcmd

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/aahan-pat/chaosify/internal/recon"
	"github.com/aahan-pat/chaosify/internal/ui"
)

// newPermissionsCmd builds `chaosify recon get permissions`, which enumerates
// the caller's effective permissions per namespace — the equivalent of running
// `kubectl auth can-i --list` across the engagement scope. It lives under `get`
// alongside the Tier 1 objects, but is itself the Tier 0 self-scoped probe.
func newPermissionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "permissions",
		Aliases: []string{"perms"},
		Short:   "List the caller's effective permissions per in-scope namespace",
		Long: `permissions reports what the connected identity is allowed to do, one
namespace at a time, mirroring 'kubectl auth can-i --list'. With no flag it walks
the engagement's in-scope namespaces; --namespaces overrides that set.`,
		RunE: runPermissions,
	}

	cmd.Flags().StringSlice("namespaces", nil,
		"Namespaces to check (default: the engagement's in-scope namespaces)")

	return cmd
}

func runPermissions(cmd *cobra.Command, _ []string) error {
	client, cfg, err := connect()
	if err != nil {
		return err
	}

	// Flag overrides the saved scope; the saved scope overrides nothing but a
	// last-resort "default" so the probe always has a namespace to check.
	namespaces, _ := cmd.Flags().GetStringSlice("namespaces")
	if len(namespaces) == 0 {
		namespaces = cfg.Namespaces
	}
	if len(namespaces) == 0 {
		namespaces = []string{"default"}
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), reconTimeout)
	defer cancel()

	ui.PrintBanner("Recon — Effective permissions")
	if cfg.Identity != "" {
		ui.PrintField("Identity", cfg.Identity)
	}

	for _, ns := range namespaces {
		perms, err := recon.ListPermissions(ctx, client, ns)
		if err != nil {
			ui.PrintError("%s: %v", ns, err)
			continue
		}

		ui.PrintTitle(ns)
		if len(perms) == 0 {
			ui.PrintInfo("  (no permissions)")
			continue
		}
		for _, p := range perms {
			ui.PrintInfo("  %s", p)
		}
	}

	return nil
}
