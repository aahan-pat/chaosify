package recon

import (
	"context"
	"fmt"
	"sort"
	"strings"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// ListPermissions returns the caller's effective permissions in the given
// namespace, mirroring `kubectl auth can-i --list -n <namespace>`. Each entry is
// formatted as "verb resource[/subresource] [resourceNames]" for resource rules
// and "verb nonResourceURL" for non-resource rules.
func ListPermissions(ctx context.Context, clientset *kubernetes.Clientset, namespace string) ([]string, error) {
	review, err := clientset.AuthorizationV1().SelfSubjectRulesReviews().Create(ctx,
		&authorizationv1.SelfSubjectRulesReview{
			Spec: authorizationv1.SelfSubjectRulesReviewSpec{Namespace: namespace},
		}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("listing permissions (SelfSubjectRulesReview) in %q: %w", namespace, err)
	}
	if review.Status.Incomplete {
		return nil, fmt.Errorf("permissions for %q are incomplete: %s", namespace, review.Status.EvaluationError)
	}

	perms := make([]string, 0)
	for _, r := range review.Status.ResourceRules {
		for _, verb := range r.Verbs {
			// A rule fans out across its API groups and resources, so emit one
			// line per verb/group/resource combination, matching kubectl.
			for _, group := range emptyToDefault(r.APIGroups) {
				for _, resource := range r.Resources {
					name := resource
					if group != "" {
						name = resource + "." + group
					}
					line := fmt.Sprintf("%s %s", verb, name)
					if len(r.ResourceNames) > 0 {
						line += " [" + strings.Join(r.ResourceNames, " ") + "]"
					}
					perms = append(perms, line)
				}
			}
		}
	}
	for _, r := range review.Status.NonResourceRules {
		for _, verb := range r.Verbs {
			for _, url := range r.NonResourceURLs {
				perms = append(perms, fmt.Sprintf("%s %s", verb, url))
			}
		}
	}

	sort.Strings(perms)
	return perms, nil
}

// emptyToDefault ensures the core ("") API group still yields one iteration so a
// rule with no explicit groups isn't silently dropped.
func emptyToDefault(groups []string) []string {
	if len(groups) == 0 {
		return []string{""}
	}
	return groups
}
