// Package kube wraps the client-go calls chaosify needs. It is split by phase:
// onboarding.go covers offline kubeconfig discovery and client construction;
// recon.go covers the connected calls that resolve identity and enumerate the
// cluster. Every call that talks to the API server takes a context.Context so
// callers control timeouts and cancellation.
package kube

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"

	"github.com/aahan-pat/chaosify/internal/types"
)

// DefaultKubeconfig resolves the conventional kubeconfig location, honoring
// $KUBECONFIG first and falling back to ~/.kube/config. It does not check that
// the file exists — that is the caller's decision to surface.
func DefaultKubeconfig() string {
	if env := os.Getenv("KUBECONFIG"); env != "" {
		// $KUBECONFIG may list several paths; the first wins for our purposes.
		return strings.Split(env, string(os.PathListSeparator))[0]
	}
	if home := homedir.HomeDir(); home != "" {
		return filepath.Join(home, ".kube", "config")
	}
	return ""
}

// ContextInfo describes one context found in a kubeconfig.
type ContextInfo struct {
	Name    string // Context name, shown in the Select.
	Cluster string // Cluster the context points at (derived, never typed).
}

// LoadContexts reads a kubeconfig and returns its contexts (sorted by name) plus
// the file's current-context. It performs no network I/O.
func LoadContexts(kubeconfigPath string) (contexts []ContextInfo, current string, err error) {
	apiCfg, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return nil, "", fmt.Errorf("reading kubeconfig %q: %w", kubeconfigPath, err)
	}
	for name, c := range apiCfg.Contexts {
		contexts = append(contexts, ContextInfo{Name: name, Cluster: c.Cluster})
	}
	sort.Slice(contexts, func(i, j int) bool { return contexts[i].Name < contexts[j].Name })
	return contexts, apiCfg.CurrentContext, nil
}

// ClusterForContext returns the cluster name a context points at, so the caller
// can echo-and-confirm it rather than asking the operator to type it.
func ClusterForContext(kubeconfigPath, contextName string) (string, error) {
	apiCfg, err := clientcmd.LoadFromFile(kubeconfigPath)
	if err != nil {
		return "", fmt.Errorf("reading kubeconfig %q: %w", kubeconfigPath, err)
	}
	ctx, ok := apiCfg.Contexts[contextName]
	if !ok {
		return "", fmt.Errorf("context %q not found in %q", contextName, kubeconfigPath)
	}
	return ctx.Cluster, nil
}

// ClientFromContext builds a Kubernetes clientset for a specific context inside a
// kubeconfig. It also returns the resolved API server URL for display.
func ClientFromContext(kubeconfigPath, contextName string) (*kubernetes.Clientset, string, error) {
	loader := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	restCfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides).ClientConfig()
	if err != nil {
		return nil, "", fmt.Errorf("building client config: %w", err)
	}
	return newClient(restCfg)
}

// ClientFromManual builds a clientset from raw connection details supplied when
// the operator declines kubeconfig discovery. TLSSkipVerify is honored verbatim;
// the caller is responsible for having logged/confirmed that choice.
func ClientFromManual(c types.Connection) (*kubernetes.Clientset, string, error) {
	restCfg := &rest.Config{
		Host:        c.Endpoint,
		BearerToken: c.Credential,
		TLSClientConfig: rest.TLSClientConfig{
			CAFile:   c.CACertPath,
			Insecure: c.TLSSkipVerify,
		},
	}
	return newClient(restCfg)
}

// newClient is the shared tail of the two client constructors.
func newClient(restCfg *rest.Config) (*kubernetes.Clientset, string, error) {
	clientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		return nil, "", fmt.Errorf("creating clientset: %w", err)
	}
	return clientset, restCfg.Host, nil
}
