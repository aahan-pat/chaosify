/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

// Package getcmd defines `chaosify recon get`, whose children each enumerate a
// single Tier 1 recon object. It is its own package so the registry (get.go),
// the shared helpers (helpers.go), and the per-object handlers (handlers.go) can
// grow without crowding the parent recon package.
//
// The package does not know how to reach the cluster; the recon parent injects a
// Connector into New so the connection logic stays in one place and there is no
// import cycle back to reconcmd.
package getcmd

import (
	"time"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"

	"github.com/aahan-pat/chaosify/internal/types"
)

// reconTimeout bounds every live API-server call a get probe makes.
const reconTimeout = 30 * time.Second

// Connector loads the saved engagement and opens a live client for it. The recon
// parent supplies one so this package doesn't duplicate connection logic.
type Connector func() (*kubernetes.Clientset, *types.Config, error)

// getCmd carries the dependencies (currently just the connector) that the
// subcommand builders close over.
type getCmd struct {
	connect Connector
}

// New builds the `recon get` command. Each child enumerates one object and is
// gated by its own can-i probe, so callers may get one type but not another.
// namespaced objects require a <namespace>; cluster-scoped objects take none.
func New(connect Connector) *cobra.Command {
	g := &getCmd{connect: connect}

	cmd := &cobra.Command{
		Use:   "get <object>",
		Short: "Enumerate a single Tier 1 recon object",
		Long: `get enumerates one Tier 1 object type at a time — the building blocks of
the recon graph. Each object is a subcommand with its own argument shape:
namespaced objects take a <namespace>, cluster-scoped objects take none.`,
	}

	cmd.AddCommand(
		// Core RBAC — the "what": permission bundles.
		g.namespacedGet("roles", "Permission bundles within a namespace", runRoles),
		g.clusterGet("clusterroles", "Cluster-scoped / reusable permission bundles", runClusterRoles),

		// Core RBAC — the "who": subject→role grants.
		g.namespacedGet("rolebindings", "Grants of a role to subjects within a namespace", runRoleBindings),
		g.clusterGet("clusterrolebindings", "Grants of a clusterrole to subjects cluster-wide", runClusterRoleBindings),

		// Identity — the non-human subjects RBAC targets.
		g.namespacedGet("serviceaccounts", "Non-human identities pods run as", runServiceAccounts),

		// Workload / placement — connects the RBAC graph to reachable compute.
		g.namespacedGet("pods", "Running workloads and their SA / escape surface", runPods),
		g.clusterGet("namespaces", "The scoping boundary enumeration iterates over", runNamespaces),

		// Credentials — SA-token secrets and general credential exposure.
		g.namespacedGet("secrets", "SA-token secrets and general credential exposure", runSecrets),
	)

	return cmd
}
