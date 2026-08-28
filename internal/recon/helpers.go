package recon

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ensureNamespaceExists reports whether namespace exists, returning a descriptive
// error when it definitively does not.
//
// It exists because listing a namespaced resource returns an empty list for both
// a missing namespace and an existing-but-empty one — the two are
// indistinguishable from the list alone. Callers invoke this only after a list
// comes back empty, to tell them apart. Any error other than a clear NotFound
// (e.g. a denied Get) is ignored so an unverifiable namespace doesn't mask the
// empty-but-real case as a failure.
func ensureNamespaceExists(ctx context.Context, clientset *kubernetes.Clientset, namespace string) error {
	if _, err := clientset.CoreV1().Namespaces().Get(ctx, namespace, metav1.GetOptions{}); apierrors.IsNotFound(err) {
		return fmt.Errorf("namespace %q does not exist", namespace)
	}
	return nil
}
