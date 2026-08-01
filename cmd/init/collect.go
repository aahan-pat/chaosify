/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

package initcmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/aahan-pat/chaosify/internal/kube"
	"github.com/aahan-pat/chaosify/internal/types"
	"github.com/aahan-pat/chaosify/internal/ui"
)

// Contains individual functions for collecting onboarding data. Seperate file to keep codebase organized.

// collectAuthorization is the first step runInit takes and the offline "hard
// gate" of Phase 1. It prompts for the engagement ID, sign-off reference, and
// the valid-from/valid-until window, then runs Validate against now. If the
// gate fails it returns an error and runInit stops here — collectConnection and
// everything connected are never reached, so chaosify never touches a cluster
// without a valid authorization window.
func collectAuthorization(cmd *cobra.Command, changed func(string) bool, cfg *types.Config) error {
	ui.PrintTitle("Authorization artifact")

	// For every field, the seed passed to the prompt is the flag's value: when
	// the flag was set it IS the answer (provided==true), and when it was not it
	// is the (empty) default that pre-fills the interactive input.
	id, err := ui.TextInput(changed("engagement-id"), mustString(cmd, "engagement-id"),
		"Engagement ID", "The client/engagement identifier.", "ENG-2026-001",
		false, NonEmpty("engagement ID"))
	if err != nil {
		return err
	}

	ref, err := ui.TextInput(changed("sign-off-ref"), mustString(cmd, "sign-off-ref"),
		"Sign-off reference", "Reference to the signed authorization document.", "SOW-#4211",
		false, NonEmpty("sign-off reference"))
	if err != nil {
		return err
	}

	fromStr, err := ui.TextInput(changed("valid-from"), mustString(cmd, "valid-from"),
		"Valid from", "Start of the authorized window (YYYY-MM-DD).", "2026-07-31",
		false, ValidateDateString)
	if err != nil {
		return err
	}
	untilStr, err := ui.TextInput(changed("valid-until"), mustString(cmd, "valid-until"),
		"Valid until", "End of the authorized window (YYYY-MM-DD).", "2026-08-31",
		false, ValidateDateString)
	if err != nil {
		return err
	}

	from, _ := ParseDate(fromStr)
	until, _ := ParseDate(untilStr)
	cfg.Authorization = types.Authorization{
		EngagementID: id, SignOffRef: ref, ValidFrom: from, ValidUntil: until,
	}

	// The hard gate: validate the window at entry. No connection happens if this
	// fails, because runInit returns before Phase 2.
	if err := Validate(cfg.Authorization, time.Now()); err != nil {
		ui.PrintError("Authorization rejected: %v", err)
		return fmt.Errorf("authorization gate failed: %w", err)
	}
	ui.PrintSuccess("Authorization valid for %s → %s",
		from.Format(DateLayout), until.Format(DateLayout))
	return nil
}

// collectConnection is the second Phase 1 step, run only after
// collectAuthorization has cleared the gate. It decides how chaosify will reach
// the cluster and delegates accordingly: collectKubeconfig for discovery from a
// kubeconfig file, or collectManual for hand-entered endpoint details. Whatever
// it records in cfg.Connection is later consumed by buildClient (in runInit) to
// open the live client that Phase 2 uses.
func collectConnection(cmd *cobra.Command, changed func(string) bool, cfg *types.Config) error {
	ui.PrintTitle("Connection & identity")

	// Manual is used only if the operator declines kubeconfig discovery (or sets
	// --manual explicitly).
	useKubeconfig := true
	if changed("manual") {
		useKubeconfig = !mustBool(cmd, "manual")
	} else {
		ok, err := ui.Confirm(false, true,
			"Discover the cluster from a kubeconfig file?",
			"Choose No only to enter endpoint details manually.", "Yes", "No")
		if err != nil {
			return err
		}
		useKubeconfig = ok
	}

	if useKubeconfig {
		return collectKubeconfig(cmd, changed, cfg)
	}
	return collectManual(cmd, changed, cfg)
}

// collectKubeconfig is the discovery branch chosen by collectConnection. It
// resolves a kubeconfig path (flag, conventional default, or file picker), lists
// the file's contexts, and records the chosen path and context in
// cfg.Connection so buildClient can construct the client from them.
func collectKubeconfig(cmd *cobra.Command, changed func(string) bool, cfg *types.Config) error {
	// Resolve the path: explicit flag wins, else the conventional default
	// ($KUBECONFIG / ~/.kube/config). If the default is missing, file-select.
	path := kube.DefaultKubeconfig()
	if changed("kubeconfig") {
		path = mustString(cmd, "kubeconfig")
	} else if _, err := os.Stat(path); err != nil {
		selected, ferr := ui.FilePick(false, "", "Select a kubeconfig file",
			"Default location was not found.", filepath.Dir(path))
		if ferr != nil {
			return ferr
		}
		path = selected
	}
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("kubeconfig not found at %q: %w", path, err)
	}
	ui.PrintSuccess("Using kubeconfig: %s", path)
	cfg.Connection.KubeconfigPath = path

	// Query the file's contexts and present them as a Select — no blind typing.
	contexts, current, err := kube.LoadContexts(path)
	if err != nil {
		return err
	}
	if len(contexts) == 0 {
		return fmt.Errorf("no contexts found in %q", path)
	}
	names := make([]string, len(contexts))
	for i, c := range contexts {
		names[i] = c.Name
	}

	// Seed with the --context flag if given, otherwise the file's current-context.
	seed := current
	if changed("context") {
		seed = mustString(cmd, "context")
	}
	chosen, err := ui.Select(changed("context"), seed,
		"Select a context", "Defaults to the kubeconfig current-context.", names)
	if err != nil {
		return err
	}
	cfg.Connection.ContextName = chosen
	ui.PrintSuccess("Context selected: %s", chosen)
	return nil
}

// collectManual is the other branch chosen by collectConnection, used when the
// operator declines kubeconfig discovery. It gathers the endpoint, CA cert, and
// bearer credential by hand and forces an explicit, logged decision on skipping
// TLS verification, storing it all in cfg.Connection for buildClient.
func collectManual(cmd *cobra.Command, changed func(string) bool, cfg *types.Config) error {
	cfg.Connection.Manual = true
	ui.PrintWarn("Manual connection mode — kubeconfig discovery skipped.")

	endpoint, err := ui.TextInput(changed("endpoint"), mustString(cmd, "endpoint"),
		"API server endpoint", "URL of the cluster API server.", "https://10.0.0.1:6443",
		false, NonEmpty("endpoint"))
	if err != nil {
		return err
	}
	caCert, err := ui.TextInput(changed("ca-cert"), mustString(cmd, "ca-cert"),
		"CA certificate path", "Path to the cluster CA certificate (leave blank to skip).", "/path/to/ca.crt",
		false, nil)
	if err != nil {
		return err
	}
	cred, err := ui.TextInput(changed("credential"), mustString(cmd, "credential"),
		"Credential (bearer token)", "Bearer token used to authenticate.", "",
		true, NonEmpty("credential"))
	if err != nil {
		return err
	}

	cfg.Connection.Endpoint = endpoint
	cfg.Connection.CACertPath = caCert
	cfg.Connection.Credential = cred

	// TLS-skip must be an explicit, logged Confirm — never a silent default.
	skip, err := ui.Confirm(changed("tls-skip-verify"), mustBool(cmd, "tls-skip-verify"),
		"Skip TLS certificate verification?",
		"DANGEROUS: disables server-certificate checking. Only for known lab targets.",
		"Skip (unsafe)", "Verify")
	if err != nil {
		return err
	}
	cfg.Connection.TLSSkipVerify = skip
	if skip {
		// Log the decision so it is on the record for the engagement.
		ui.PrintWarn("TLS verification DISABLED by operator confirmation at %s",
			time.Now().Format(time.RFC3339))
	}
	return nil
}

// verifyIdentity opens Phase 2 (connected) — it is the first call runInit makes
// after buildClient produces a live client. It echoes the identity the cluster
// reports (kube.WhoAmI) and makes the operator confirm it before any recon
// proceeds to collectCluster. A declined identity aborts onboarding.
func verifyIdentity(client *clientset, cfg *types.Config) error {
	ui.PrintTitle("Identity")
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	who, err := kube.WhoAmI(ctx, client)
	if err != nil {
		ui.PrintError("Could not verify identity: %v", err)
		return err
	}
	cfg.Identity = who
	ui.PrintSuccess("Connected as %s", who)

	ok, err := ui.Confirm(false, true, "Is this the identity you expect?",
		"Confirm before chaosify proceeds with recon.", "Yes", "No")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("identity not confirmed by operator")
	}
	return nil
}

// collectCluster runs after verifyIdentity. It derives the cluster's name and
// API-server host, echoes them, and has the operator confirm they want to
// proceed against this cluster before scope selection begins in
// collectNamespaces. A declined cluster aborts onboarding.
func collectCluster(cfg *types.Config, host string) error {
	ui.PrintTitle("Cluster")

	cluster := host // Manual mode: the endpoint is the best identifier we have.
	if !cfg.Connection.Manual {
		if name, err := kube.ClusterForContext(cfg.Connection.KubeconfigPath, cfg.Connection.ContextName); err == nil && name != "" {
			cluster = name
		}
	}
	cfg.Cluster = cluster
	ui.PrintField("Cluster", cluster)
	ui.PrintField("API server", host)

	ok, err := ui.Confirm(false, true, "Proceed against this cluster?", "", "Yes", "No")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("cluster not confirmed by operator")
	}
	return nil
}

// collectNamespaces is the scope step, run after collectCluster is confirmed. It
// lists the namespaces the identity can read (falling back to just "default" if
// listing is denied) and lets the operator choose the in-scope set. That set is
// the input collectDenylist narrows next, and the scope collectRunMode requires
// before it will allow active mode.
func collectNamespaces(cmd *cobra.Command, changed func(string) bool, client *clientset, cfg *types.Config) error {
	ui.PrintTitle("Namespace scope")
	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()

	all, err := kube.ListNamespaces(ctx, client)
	if err != nil {
		// Listing denied → fall back to "default" only, per the runbook.
		ui.PrintWarn("Cannot list namespaces (%v); falling back to \"default\".", err)
		cfg.Namespaces = []string{"default"}
		return nil
	}

	// "Sweep all" default: every readable namespace starts pre-checked.
	provided := mustStringSlice(cmd, "namespaces")
	selected, err := ui.MultiSelect(changed("namespaces"), provided,
		"Select in-scope namespaces",
		"All are pre-checked (sweep-all). Uncheck any that are out of scope.",
		all, all)
	if err != nil {
		return err
	}
	if len(selected) == 0 {
		ui.PrintWarn("No namespaces selected — scope is empty.")
	}
	cfg.Namespaces = selected
	ui.PrintSuccess("%d namespace(s) in scope", len(selected))
	return nil
}

// collectDenylist runs right after collectNamespaces and narrows its result. It
// offers the in-scope namespaces as a stop-list to exclude, plus optional finer
// resource/action deny rules. Together these define what chaosify will never
// touch, regardless of the run mode chosen next in collectRunMode.
func collectDenylist(cmd *cobra.Command, changed func(string) bool, cfg *types.Config) error {
	ui.PrintTitle("Stop list / denylist")

	// Reuse the in-scope namespace list as the denylist options; default none.
	provided := mustStringSlice(cmd, "denylist")
	deny, err := ui.MultiSelect(changed("denylist"), provided,
		"Namespaces to exclude (stop list)",
		"Default none. Checked namespaces will never be touched.",
		cfg.Namespaces, nil)
	if err != nil {
		return err
	}
	cfg.Denylist = deny

	// Finer free-text rules are optional (resource/action level).
	rules := mustStringSlice(cmd, "deny-rules")
	if changed("deny-rules") {
		cfg.DenyRules = rules
	} else {
		raw, err := ui.TextInput(false, "",
			"Additional deny rules (optional)",
			"Comma-separated resource/action rules, e.g. \"secrets:delete, pods:exec\". Leave blank for none.",
			"", false, nil)
		if err != nil {
			return err
		}
		cfg.DenyRules = splitCSV(raw)
	}
	return nil
}

// collectRunMode runs after the scope and stop-list are set. It selects dry-run
// (enumerate and report only) or active (mutating/testing actions). Active is
// gated: it requires the non-empty scope from collectNamespaces and a separate
// explicit confirmation, otherwise it reverts to dry-run.
func collectRunMode(cmd *cobra.Command, changed func(string) bool, cfg *types.Config) error {
	ui.PrintTitle("Run mode")

	seed := string(types.RunModeDryRun)
	if changed("run-mode") {
		seed = mustString(cmd, "run-mode")
	}
	mode, err := ui.Select(changed("run-mode"), seed, "Select run mode",
		"dry-run enumerates and reports only. active permits testing actions.",
		[]string{string(types.RunModeDryRun), string(types.RunModeActive)})
	if err != nil {
		return err
	}
	cfg.RunMode = types.RunMode(mode)

	if cfg.RunMode == types.RunModeActive {
		// Active requires a configured scope and stop-list, then a confirmation.
		if len(cfg.Namespaces) == 0 {
			return fmt.Errorf("active mode requires a non-empty namespace scope")
		}
		ok, err := ui.Confirm(false, false,
			"Enable ACTIVE mode against this cluster?",
			"Active mode performs mutating/testing actions within the configured scope.",
			"Enable active", "Stay dry-run")
		if err != nil {
			return err
		}
		if !ok {
			cfg.RunMode = types.RunModeDryRun
			ui.PrintInfo("Reverted to dry-run.")
		} else {
			ui.PrintWarn("ACTIVE mode enabled at %s", time.Now().Format(time.RFC3339))
		}
	}
	return nil
}

// collectExpectedPrivilege is the last collector, run after collectRunMode and
// just before runInit hands off to echoSummary. It optionally records the
// privilege level the engagement expects to have (for later reconciliation);
// skipping it defaults to enumerate-and-report with no reconciliation.
func collectExpectedPrivilege(cmd *cobra.Command, changed func(string) bool, cfg *types.Config) error {
	ui.PrintTitle("Expected privilege level (optional)")

	const defaultLevel = "enumerate-and-report"
	if changed("expected-privilege") {
		cfg.ExpectedPrivilege = mustString(cmd, "expected-privilege")
		return nil
	}

	// Skippable: default is enumerate-and-report with no reconciliation.
	set, err := ui.Confirm(false, false, "Set an expected privilege level?",
		"Skip to use the default (enumerate-and-report, no reconciliation).",
		"Set level", "Skip")
	if err != nil {
		return err
	}
	if !set {
		cfg.ExpectedPrivilege = defaultLevel
		return nil
	}
	level, err := ui.Select(false, defaultLevel, "Expected privilege level", "",
		[]string{defaultLevel, "view", "edit", "namespace-admin", "cluster-admin"})
	if err != nil {
		return err
	}
	cfg.ExpectedPrivilege = level
	return nil
}
