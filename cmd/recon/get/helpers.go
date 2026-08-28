/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

package getcmd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/client-go/kubernetes"

	"github.com/aahan-pat/chaosify/internal/recon"
	"github.com/aahan-pat/chaosify/internal/ui"
)

// This file holds the shared helpers behind `recon get`: the subcommand builders
// that wrap every object, the not-implemented placeholders, and the output
// renderers. The per-object handlers that use them live in handlers.go.

// namespacedRun enumerates a namespaced object within a single namespace.
type namespacedRun func(ctx context.Context, client *kubernetes.Clientset, namespace string) error

// clusterRun enumerates a cluster-scoped object, which needs no namespace.
type clusterRun func(ctx context.Context, client *kubernetes.Clientset) error

// namespacedGet builds a get subcommand for a namespaced object. The namespace
// is the sole positional argument, so arity is pinned at exactly one and the
// run func can rely on args[0] being present.
func (g *getCmd) namespacedGet(object, short string, run namespacedRun) *cobra.Command {
	return &cobra.Command{
		Use:   object + " <namespace>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, _, err := g.connect()
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
func (g *getCmd) clusterGet(object, short string, run clusterRun) *cobra.Command {
	return &cobra.Command{
		Use:   object,
		Short: short,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, _, err := g.connect()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), reconTimeout)
			defer cancel()
			return run(ctx, client)
		},
	}
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

// printRolePermissions renders a name -> permissions map as a grouped list: each
// role name is a heading with its permissions indented beneath it. Both the role
// names and each role's permissions are sorted so the output is stable run to
// run (a raw map iterates in random order). object names the kind for the empty
// message, e.g. "roles" or "clusterroles".
func printRolePermissions(roles map[string][]string, object string) {
	if len(roles) == 0 {
		ui.PrintInfo("(no %s)", object)
		return
	}

	names := make([]string, 0, len(roles))
	for name := range roles {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		perms := append([]string(nil), roles[name]...)
		sort.Strings(perms)

		fmt.Println()
		ui.PrintTitle(name)
		if len(perms) == 0 {
			ui.PrintItem("(no permissions)")
			continue
		}
		for _, p := range perms {
			ui.PrintItem("%s", p)
		}
	}
}

// printBindings renders a slice of bindings: each binding name is a heading, with
// its granted role and the subjects it grants to indented beneath. recon already
// sorts the bindings by name; subjects keep their declared order. object names the
// kind for the empty message, e.g. "rolebindings" or "clusterrolebindings".
func printBindings(bindings []recon.Binding, object string) {
	if len(bindings) == 0 {
		ui.PrintInfo("(no %s)", object)
		return
	}

	for _, b := range bindings {
		fmt.Println()
		ui.PrintTitle(b.Name)
		ui.PrintItem("→ %s", b.RoleRef)
		if len(b.Subjects) == 0 {
			ui.PrintItem("(no subjects)")
			continue
		}
		for _, s := range b.Subjects {
			ui.PrintItem("%s", s)
		}
	}
}

// printServiceAccounts renders a slice of serviceaccounts: each SA name is a
// heading, with its token-automount setting and referenced secrets indented
// beneath. recon already sorts the SAs by name. object names the kind for the
// empty message.
func printServiceAccounts(sas []recon.ServiceAccount, object string) {
	if len(sas) == 0 {
		ui.PrintInfo("(no %s)", object)
		return
	}

	for _, sa := range sas {
		fmt.Println()
		ui.PrintTitle(sa.Name)
		ui.PrintItem("automount token: %s", sa.AutomountToken)
		ui.PrintItem("secrets: %s", joinOrNone(sa.Secrets))
		ui.PrintItem("image-pull secrets: %s", joinOrNone(sa.ImagePullSecrets))
	}
}

// printPods renders a slice of pods: each pod name is a heading, with the
// identity it runs as and its escape surface (host namespaces, privileged
// containers) indented beneath. recon already sorts the pods by name.
func printPods(pods []recon.Pod, object string) {
	if len(pods) == 0 {
		ui.PrintInfo("(no %s)", object)
		return
	}

	for _, p := range pods {
		fmt.Println()
		ui.PrintTitle(p.Name)
		ui.PrintItem("serviceaccount: %s", p.ServiceAccount)
		ui.PrintItem("node: %s", valueOrNone(p.Node))
		ui.PrintItem("host namespaces: %s", joinOrNone(p.HostNamespaces))
		ui.PrintItem("privileged containers: %s", joinOrNone(p.PrivilegedContainers))
	}
}

// printSecrets renders a slice of secrets: each secret name is a heading, with
// its type, owning serviceaccount (for SA-token secrets), and data key names
// indented beneath. Values are never part of the model and so never printed.
func printSecrets(secrets []recon.Secret, object string) {
	if len(secrets) == 0 {
		ui.PrintInfo("(no %s)", object)
		return
	}

	for _, s := range secrets {
		fmt.Println()
		ui.PrintTitle(s.Name)
		ui.PrintItem("type: %s", s.Type)
		if s.ServiceAccount != "" {
			ui.PrintItem("serviceaccount: %s", s.ServiceAccount)
		}
		ui.PrintItem("keys: %s", joinOrNone(s.Keys))
	}
}

// valueOrNone renders a string as-is, or "(none)" when empty, so an absent scalar
// reads clearly instead of as a trailing blank.
func valueOrNone(v string) string {
	if v == "" {
		return "(none)"
	}
	return v
}

// joinOrNone renders a string slice as a comma-separated list, or "(none)" when
// empty, so an absent set reads clearly instead of as a blank line.
func joinOrNone(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return strings.Join(items, ", ")
}
