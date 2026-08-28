/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

package getcmd

import (
	"context"

	"k8s.io/client-go/kubernetes"

	"github.com/aahan-pat/chaosify/internal/recon"
	"github.com/aahan-pat/chaosify/internal/ui"
)

// This file holds the per-object `recon get` handlers — one run func per object.
// They retrieve through internal/recon and render through the helpers in
// helpers.go. Wire a new handler into the registry in get.go.

// runRoles enumerates the roles defined in a single namespace.
func runRoles(ctx context.Context, client *kubernetes.Clientset, namespace string) error {
	found, err := recon.ListRoles(ctx, client, namespace)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — Roles")
	ui.PrintField("Namespace", namespace)
	printRolePermissions(found, "roles")
	return nil
}

// runClusterRoles enumerates the cluster-scoped clusterroles. It mirrors
// runRoles but takes no namespace, since clusterroles are not namespaced.
func runClusterRoles(ctx context.Context, client *kubernetes.Clientset) error {
	found, err := recon.ListClusterRoles(ctx, client)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — ClusterRoles")
	printRolePermissions(found, "clusterroles")
	return nil
}

// runRoleBindings enumerates the rolebindings defined in a single namespace —
// which subjects are granted which role within that namespace.
func runRoleBindings(ctx context.Context, client *kubernetes.Clientset, namespace string) error {
	found, err := recon.ListRoleBindings(ctx, client, namespace)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — RoleBindings")
	ui.PrintField("Namespace", namespace)
	printBindings(found, "rolebindings")
	return nil
}

// runClusterRoleBindings enumerates the cluster-scoped clusterrolebindings. It
// mirrors runRoleBindings but takes no namespace.
func runClusterRoleBindings(ctx context.Context, client *kubernetes.Clientset) error {
	found, err := recon.ListClusterRoleBindings(ctx, client)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — ClusterRoleBindings")
	printBindings(found, "clusterrolebindings")
	return nil
}

// runServiceAccounts enumerates the serviceaccounts defined in a single
// namespace — the non-human identities pods run as and bindings grant to.
func runServiceAccounts(ctx context.Context, client *kubernetes.Clientset, namespace string) error {
	found, err := recon.ListServiceAccounts(ctx, client, namespace)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — ServiceAccounts")
	ui.PrintField("Namespace", namespace)
	printServiceAccounts(found, "serviceaccounts")
	return nil
}

// runPods enumerates the pods in a single namespace — the running workloads,
// the identity each runs as, and its container-escape surface.
func runPods(ctx context.Context, client *kubernetes.Clientset, namespace string) error {
	found, err := recon.ListPods(ctx, client, namespace)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — Pods")
	ui.PrintField("Namespace", namespace)
	printPods(found, "pods")
	return nil
}

// runSecrets enumerates the secrets in a single namespace — SA-token secrets and
// general credential exposure. Secret values are never read or shown.
func runSecrets(ctx context.Context, client *kubernetes.Clientset, namespace string) error {
	found, err := recon.ListSecrets(ctx, client, namespace)
	if err != nil {
		return err
	}

	ui.PrintBanner("Recon — Secrets")
	ui.PrintField("Namespace", namespace)
	printSecrets(found, "secrets")
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
