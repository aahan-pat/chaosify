package recon

import (
	"context"
	"fmt"
	"strings"

	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// WhoAmI resolves the caller's identity via a SelfSubjectReview. This is both the
// identity echo ("Connected as ...") and chaosify's first recon call, so a
// failure here is a genuine connection/authentication problem.
func WhoAmI(ctx context.Context, clientset *kubernetes.Clientset) (string, error) {
	review, err := clientset.AuthenticationV1().SelfSubjectReviews().
		Create(ctx, &authv1.SelfSubjectReview{}, metav1.CreateOptions{})
	if err != nil {
		return "", fmt.Errorf("resolving identity (SelfSubjectReview): %w", err)
	}
	user := review.Status.UserInfo.Username
	if user == "" {
		user = "<unknown>"
	}
	if len(review.Status.UserInfo.Groups) > 0 {
		return fmt.Sprintf("%s (groups: %s)", user,
			strings.Join(review.Status.UserInfo.Groups, ", ")), nil
	}
	return user, nil
}
