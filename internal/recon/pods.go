package recon

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Pod is a plain-value view of a running workload. It captures the two things
// recon cares about: the identity the pod runs as (ServiceAccount — the join back
// to the RBAC graph) and its container-escape surface (host namespaces and any
// privileged containers — the ways a compromise reaches the node).
type Pod struct {
	Name                 string   // The pod's name.
	ServiceAccount       string   // The SA the pod runs as ("default" when unset).
	Node                 string   // The node the pod is scheduled on ("" when unscheduled).
	HostNamespaces       []string // Host namespaces the pod shares: any of "hostNetwork", "hostPID", "hostIPC".
	PrivilegedContainers []string // Names of containers (incl. init) running privileged.
}

// ListPods returns every pod in the given namespace, sorted by name. It mirrors
// ListRoles: an empty list is disambiguated from a missing namespace with
// ensureNamespaceExists.
func ListPods(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]Pod, error) {
	list, err := clientset.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing pods in %q: %w", namespace, err)
	}

	if len(list.Items) == 0 {
		if err := ensureNamespaceExists(ctx, clientset, namespace); err != nil {
			return nil, err
		}
	}

	out := make([]Pod, 0, len(list.Items))
	for _, pod := range list.Items {
		sa := pod.Spec.ServiceAccountName
		if sa == "" {
			sa = "default"
		}

		out = append(out, Pod{
			Name:                 pod.Name,
			ServiceAccount:       sa,
			Node:                 pod.Spec.NodeName,
			HostNamespaces:       hostNamespaces(pod.Spec),
			PrivilegedContainers: privilegedContainers(pod.Spec),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// hostNamespaces lists which of the node's namespaces the pod shares. Sharing any
// of them collapses the isolation boundary between the pod and the host.
func hostNamespaces(spec corev1.PodSpec) []string {
	var shared []string
	if spec.HostNetwork {
		shared = append(shared, "hostNetwork")
	}
	if spec.HostPID {
		shared = append(shared, "hostPID")
	}
	if spec.HostIPC {
		shared = append(shared, "hostIPC")
	}
	return shared
}

// privilegedContainers returns the names of every container in the pod — init
// containers included — whose SecurityContext requests privileged mode, the most
// direct container-to-node escape.
func privilegedContainers(spec corev1.PodSpec) []string {
	var priv []string
	for _, c := range append(append([]corev1.Container(nil), spec.InitContainers...), spec.Containers...) {
		if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
			priv = append(priv, c.Name)
		}
	}
	return priv
}
