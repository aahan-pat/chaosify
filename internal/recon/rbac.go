package recon

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

	// List returns an empty slice for both a missing namespace and an existing
	// but empty one, so check the namespace explicitly to tell them apart.
	if len(roles.Items) == 0 {
		if _, nsErr := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{}); apierrors.IsNotFound(nsErr) {
			return nil, fmt.Errorf("namespace %q does not exist", namespace)
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