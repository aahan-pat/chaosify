/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

package reconcmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"

	"github.com/aahan-pat/chaosify/internal/recon"
	"github.com/aahan-pat/chaosify/internal/ui"
)

// newGetCmd builds `chaosify recon get`, whose children each enumerate a single
// Tier 1 object — the building blocks of the recon graph. Every object is its
// own subcommand so cobra enforces the object's argument shape before RunE ever
// runs: namespaced objects require a <namespace>, cluster-scoped objects take
// none. Each object is also independently gated by its own can-i probe, so you
// may be able to get one type but not another.
func newGetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <object>",
		Short: "Enumerate a single Tier 1 recon object",
		Long: `get enumerates one Tier 1 object type at a time — the building blocks of
the recon graph. Each object is a subcommand with its own argument shape:
namespaced objects take a <namespace>, cluster-scoped objects take none.`,
	}

	cmd.AddCommand(
		// Core RBAC — the "what": permission bundles.
		namespacedGet("roles", "Permission bundles within a namespace", runRoles),
		clusterGet("clusterroles", "Cluster-scoped / reusable permission bundles", notImplementedCluster("clusterroles")),

		// Core RBAC — the "who": subject→role grants.
		namespacedGet("rolebindings", "Grants of a role to subjects within a namespace", notImplementedNamespaced("rolebindings")),
		clusterGet("clusterrolebindings", "Grants of a clusterrole to subjects cluster-wide", notImplementedCluster("clusterrolebindings")),

		// Identity — the non-human subjects RBAC targets.
		namespacedGet("serviceaccounts", "Non-human identities pods run as", notImplementedNamespaced("serviceaccounts")),

		// Workload / placement — connects the RBAC graph to reachable compute.
		namespacedGet("pods", "Running workloads and their SA / escape surface", notImplementedNamespaced("pods")),
		clusterGet("namespaces", "The scoping boundary enumeration iterates over", runNamespaces),

		// Credentials — SA-token secrets and general credential exposure.
		namespacedGet("secrets", "SA-token secrets and general credential exposure", notImplementedNamespaced("secrets")),

		// Fallback subject when cluster RBAC read fails (Tier 0).
		clusterGet("selfsubjectrules", "The caller's own effective rules (RBAC-read fallback)", notImplementedCluster("selfsubjectrules")),
	)

	return cmd
}

// namespacedRun enumerates a namespaced object within a single namespace.
type namespacedRun func(ctx context.Context, client *kubernetes.Clientset, namespace string) error

// clusterRun enumerates a cluster-scoped object, which needs no namespace.
type clusterRun func(ctx context.Context, client *kubernetes.Clientset) error

// namespacedGet builds a get subcommand for a namespaced object. The namespace
// is the sole positional argument, so arity is pinned at exactly one and the
// run func can rely on args[0] being present.
func namespacedGet(object, short string, run namespacedRun) *cobra.Command {
	return &cobra.Command{
		Use:   object + " <namespace>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, err := connect()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), reconTimeout)
			defer cancel()
			return run(ctx, client, args[0])
		},
	}
}

// clusterGet builds a get subcommand for a cluster-scoped object. It takes no
// positional arguments, so cobra rejects a stray namespace before RunE runs.
func clusterGet(object, short string, run clusterRun) *cobra.Command {
	return &cobra.Command{
		Use:   object,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, err := connect()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), reconTimeout)
			defer cancel()
			return run(ctx, client)
		},
	}
}

// runRoles enumerates the roles defined in a single namespace.
func runRoles(ctx context.Context, client *kubernetes.Clientset, namespace string) error {
	found, err := recon.ListRoles(ctx, client, namespace)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — Roles")
	ui.PrintField("Namespace", namespace)
	if len(found) == 0 {
		ui.PrintInfo("  (no roles)")
		return nil
	}
	for _, r := range found {
		ui.PrintInfo("  %s", r)
	}
	return nil
}

// runNamespaces enumerates the namespaces the caller can see cluster-wide.
func runNamespaces(ctx context.Context, client *kubernetes.Clientset) error {
	found, err := recon.ListNamespaces(ctx, client)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — Namespaces")
	if len(found) == 0 {
		ui.PrintInfo("  (no namespaces)")
		return nil
	}
	for _, ns := range found {
		ui.PrintInfo("  %s", ns)
	}
	return nil
}

// notImplementedNamespaced returns a namespaced run that errors until the
// object's enumeration is wired in. Arity is still enforced by the subcommand,
// so the contract holds before the implementation lands.
func notImplementedNamespaced(object string) namespacedRun {
	return func(context.Context, *kubernetes.Clientset, string) error {
		return notImplemented(object)
	}
}

// notImplementedCluster is the cluster-scoped counterpart to
// notImplementedNamespaced.
func notImplementedCluster(object string) clusterRun {
	return func(context.Context, *kubernetes.Clientset) error {
		return notImplemented(object)
	}
}

// notImplemented is the placeholder every unwired object dispatches to.
func notImplemented(object string) error {
	return fmt.Errorf("get %s: not implemented yet", object)
}
