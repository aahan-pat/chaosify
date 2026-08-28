package recon

import (
	"context"
	"fmt"
	"sort"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// serviceAccountNameAnnotation ties a service-account-token secret back to the SA
// it holds a token for.
const serviceAccountNameAnnotation = "kubernetes.io/service-account.name"

// Secret is a plain-value view of a Kubernetes Secret. It deliberately records
// only metadata — name, type, owning ServiceAccount, and the data *key* names —
// and never the values. Recon reports that a credential exists and what kind it
// is; it does not exfiltrate its contents.
type Secret struct {
	Name           string   // The secret's name.
	Type           string   // The secret type, e.g. "kubernetes.io/service-account-token" or "Opaque".
	ServiceAccount string   // For SA-token secrets, the SA it belongs to; "" otherwise.
	Keys           []string // Data key names only — never the values behind them.
}

// ListSecrets returns every secret in the given namespace, sorted by name. It
// mirrors ListRoles: an empty list is disambiguated from a missing namespace with
// ensureNamespaceExists. Secret *values* are never read into the result.
func ListSecrets(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]Secret, error) {
	list, err := clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing secrets in %q: %w", namespace, err)
	}

	if len(list.Items) == 0 {
		if err := ensureNamespaceExists(ctx, clientset, namespace); err != nil {
			return nil, err
		}
	}

	out := make([]Secret, 0, len(list.Items))
	for _, s := range list.Items {
		keys := make([]string, 0, len(s.Data))
		for k := range s.Data {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		out = append(out, Secret{
			Name:           s.Name,
			Type:           string(s.Type),
			ServiceAccount: s.Annotations[serviceAccountNameAnnotation],
			Keys:           keys,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}
