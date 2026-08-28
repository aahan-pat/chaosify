package recon

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ServiceAccount is a plain-value view of a Kubernetes ServiceAccount — the
// non-human identity that pods run as and that RBAC bindings grant to. The fields
// captured are the security-relevant ones: whether a token is auto-mounted into
// pods using this SA, and the secrets it references.
type ServiceAccount struct {
	Name             string   // The ServiceAccount's name.
	AutomountToken   string   // Token auto-mount into pods: "true", "false", or "unset (defaults to true)".
	Secrets          []string // Names of secrets the SA references (legacy tokens / mountable secrets).
	ImagePullSecrets []string // Names of image-pull secrets the SA references.
}

// ListServiceAccounts returns every ServiceAccount in the given namespace,
// sorted by name. It mirrors ListRoles: an empty list is disambiguated from a
// missing namespace with ensureNamespaceExists.
func ListServiceAccounts(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]ServiceAccount, error) {
	list, err := clientset.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing serviceaccounts in %q: %w", namespace, err)
	}

	if len(list.Items) == 0 {
		if err := ensureNamespaceExists(ctx, clientset, namespace); err != nil {
			return nil, err
		}
	}

	out := make([]ServiceAccount, 0, len(list.Items))
	for _, sa := range list.Items {
		secrets := make([]string, 0, len(sa.Secrets))
		for _, s := range sa.Secrets {
			secrets = append(secrets, s.Name)
		}
		pullSecrets := make([]string, 0, len(sa.ImagePullSecrets))
		for _, s := range sa.ImagePullSecrets {
			pullSecrets = append(pullSecrets, s.Name)
		}

		out = append(out, ServiceAccount{
			Name:             sa.Name,
			AutomountToken:   formatAutomount(sa.AutomountServiceAccountToken),
			Secrets:          secrets,
			ImagePullSecrets: pullSecrets,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// formatAutomount renders the SA's AutomountServiceAccountToken tri-state. A nil
// pointer means the field is unset, in which case Kubernetes defaults to mounting
// the token — a security-relevant distinction worth spelling out rather than
// flattening to a bare "true".
func formatAutomount(b *bool) string {
	switch {
	case b == nil:
		return "unset (defaults to true)"
	case *b:
		return "true"
	default:
		return "false"
	}
}
