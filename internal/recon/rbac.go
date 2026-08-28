package recon

import (
	"context"
	"fmt"
	"sort"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ListRoles returns a map of role name -> its permission strings for every Role
// in the given namespace. Each permission is formatted "verb resource[.group]".
func ListRoles(ctx context.Context, clientset *kubernetes.Clientset, namespace string) (map[string][]string, error) {
	roles, err := clientset.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing roles in %q: %w", namespace, err)
	}

	if len(roles.Items) == 0 {
		if err := ensureNamespaceExists(ctx, clientset, namespace); err != nil {
			return nil, err
		}
	}

	out := make(map[string][]string, len(roles.Items))
	for _, role := range roles.Items {
		var perms []string
		// A PolicyRule fans out across verbs, API groups, and resources, so emit
		// one line per combination (same shape as ListPermissions).
		for _, rule := range role.Rules {
			for _, verb := range rule.Verbs {
				for _, group := range emptyToDefault(rule.APIGroups) {
					for _, resource := range rule.Resources {
						name := resource
						if group != "" {
							name = resource + "." + group
						}
						perms = append(perms, fmt.Sprintf("%s %s", verb, name))
					}
				}
			}
		}
		out[role.Name] = perms
	}
	return out, nil
}

// Binding is a plain-value view of a (Cluster)RoleBinding: the grant that ties a
// set of subjects to one role. RoleRef and Subjects are pre-formatted strings so
// nothing downstream has to know the Kubernetes type system, matching the rest of
// internal/recon.
type Binding struct {
	Name     string   // The binding's own name.
	RoleRef  string   // The granted role, formatted "Kind/Name" (e.g. "ClusterRole/view").
	Subjects []string // Who receives it, each "Kind/Name" or "Kind/Name (ns: X)".
}

// ListRoleBindings returns every RoleBinding in the given namespace as a Binding,
// sorted by name. Each Binding records which role it grants (RoleRef) and to whom
// (Subjects) — the edges that connect subjects to the permission bundles ListRoles
// enumerates. Formatting mirrors ListRoles: an empty list is disambiguated from a
// missing namespace with an explicit Get.
func ListRoleBindings(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]Binding, error) {
	bindings, err := clientset.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing rolebindings in %q: %w", namespace, err)
	}

	if len(bindings.Items) == 0 {
		if err := ensureNamespaceExists(ctx, clientset, namespace); err != nil {
			return nil, err
		}
	}

	out := make([]Binding, 0, len(bindings.Items))
	for _, rb := range bindings.Items {
		out = append(out, Binding{
			Name:     rb.Name,
			RoleRef:  fmt.Sprintf("%s/%s", rb.RoleRef.Kind, rb.RoleRef.Name),
			Subjects: formatSubjects(rb.Subjects),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// ListClusterRoleBindings returns every ClusterRoleBinding in the cluster as a
// Binding, sorted by name. ClusterRoleBindings are cluster-scoped, so there is no
// namespace and no missing-namespace check; otherwise it mirrors ListRoleBindings.
func ListClusterRoleBindings(ctx context.Context, clientset *kubernetes.Clientset) ([]Binding, error) {
	bindings, err := clientset.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing clusterrolebindings: %w", err)
	}

	out := make([]Binding, 0, len(bindings.Items))
	for _, crb := range bindings.Items {
		out = append(out, Binding{
			Name:     crb.Name,
			RoleRef:  fmt.Sprintf("%s/%s", crb.RoleRef.Kind, crb.RoleRef.Name),
			Subjects: formatSubjects(crb.Subjects),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// formatSubjects renders a binding's subjects as plain strings. A subject's
// namespace only applies to ServiceAccounts (Users and Groups are cluster-wide),
// so it is appended only when present.
func formatSubjects(subjects []rbacv1.Subject) []string {
	out := make([]string, 0, len(subjects))
	for _, s := range subjects {
		line := fmt.Sprintf("%s/%s", s.Kind, s.Name)
		if s.Namespace != "" {
			line += fmt.Sprintf(" (ns: %s)", s.Namespace)
		}
		out = append(out, line)
	}
	return out
}

// ListClusterRoles returns a map of clusterrole name -> its permission strings
// for every ClusterRole in the cluster. Each permission is formatted
// "verb resource[.group]", mirroring ListRoles. ClusterRoles are cluster-scoped,
// so there is no namespace and no missing-namespace check.
func ListClusterRoles(ctx context.Context, clientset *kubernetes.Clientset) (map[string][]string, error) {
	clusterRoles, err := clientset.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing clusterroles: %w", err)
	}

	out := make(map[string][]string, len(clusterRoles.Items))
	for _, cr := range clusterRoles.Items {
		var perms []string
		// Same verb/apiGroup/resource fan-out as ListRoles.
		for _, rule := range cr.Rules {
			for _, verb := range rule.Verbs {
				for _, group := range emptyToDefault(rule.APIGroups) {
					for _, resource := range rule.Resources {
						name := resource
						if group != "" {
							name = resource + "." + group
						}
						perms = append(perms, fmt.Sprintf("%s %s", verb, name))
					}
				}
			}
		}
		out[cr.Name] = perms
	}
	return out, nil
}