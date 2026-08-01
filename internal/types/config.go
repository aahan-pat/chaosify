// Package types holds the shared data structures that describe a chaosify
// engagement. These are plain, dependency-free structs so they can be imported
// by any layer (UI, kube, persistence) without creating import cycles.
package types

import "time"

// RunMode controls how aggressively chaosify interacts with the cluster.
type RunMode string

const (
	// RunModeDryRun enumerates and reports only; it performs no mutating or
	// active actions. This is the safe default.
	RunModeDryRun RunMode = "dry-run"
	// RunModeActive permits active testing actions and therefore requires an
	// explicit confirmation plus a configured scope and stop-list.
	RunModeActive RunMode = "active"
)

// Authorization is the engagement's paper trail (Phase 1). It is collected and
// validated entirely offline, before any connection is attempted.
type Authorization struct {
	EngagementID string    // Client/engagement identifier.
	SignOffRef   string    // Reference to the signed authorization document.
	ValidFrom    time.Time // Start of the authorized testing window.
	ValidUntil   time.Time // End of the authorized testing window.
}

// Connection describes how to reach the target cluster. The kubeconfig path is
// the primary route; the Manual* fields are only populated when the operator
// declines kubeconfig discovery and provides raw connection details.
type Connection struct {
	KubeconfigPath string // Path to the kubeconfig file (primary route).
	ContextName    string // Selected context within the kubeconfig.

	// Manual fallback. Manual is true when the operator supplied raw endpoint
	// details instead of a kubeconfig.
	Manual        bool
	Endpoint      string // API server URL, e.g. https://10.0.0.1:6443
	CACertPath    string // Path to the cluster CA certificate.
	Credential    string // Bearer token or path to a credential file.
	TLSSkipVerify bool   // Skip TLS verification. Dangerous; must be confirmed.
}

// Config is the complete, resolved onboarding state for a single engagement.
type Config struct {
	Authorization Authorization
	Connection    Connection

	Identity string // "Connected as ..." resolved via SelfSubjectReview.
	Cluster  string // Derived from the selected context, never typed.

	Namespaces []string // In-scope namespaces (the "sweep" set).
	Denylist   []string // Namespaces explicitly excluded from testing.
	DenyRules  []string // Finer free-text resource/action exclusion rules.

	RunMode           RunMode // dry-run (default) or active.
	ExpectedPrivilege string  // Optional expected privilege level.
}
