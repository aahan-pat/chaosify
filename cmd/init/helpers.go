/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

package initcmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/aahan-pat/chaosify/internal/kube"
	"github.com/aahan-pat/chaosify/internal/types"
	"github.com/aahan-pat/chaosify/internal/ui"
)

// runSteps runs each onboarding step in order and returns the first error,
// leaving runInit free of the repeated `if err := step(); err != nil` block.
func runSteps(steps ...func() error) error {
	for _, step := range steps {
		if err := step(); err != nil {
			return err
		}
	}
	return nil
}

// buildClient constructs the clientset from whichever source Phase 1 produced.
func buildClient(cfg *types.Config) (client *clientset, host string, err error) {
	if cfg.Connection.Manual {
		return kube.ClientFromManual(cfg.Connection)
	}
	return kube.ClientFromContext(cfg.Connection.KubeconfigPath, cfg.Connection.ContextName)
}

// echoSummary prints the final onboarding recap.
func echoSummary(cfg *types.Config) {
	ui.PrintBanner("Onboarding complete")
	ui.PrintField("Engagement", cfg.Authorization.EngagementID)
	ui.PrintField("Sign-off", cfg.Authorization.SignOffRef)
	ui.PrintField("Window", fmt.Sprintf("%s → %s",
		cfg.Authorization.ValidFrom.Format(DateLayout),
		cfg.Authorization.ValidUntil.Format(DateLayout)))
	ui.PrintField("Identity", cfg.Identity)
	ui.PrintField("Cluster", cfg.Cluster)
	ui.PrintField("Scope", fmt.Sprintf("%d namespace(s)", len(cfg.Namespaces)))
	if len(cfg.Denylist) > 0 {
		ui.PrintField("Stop list", strings.Join(cfg.Denylist, ", "))
	}
	ui.PrintField("Run mode", string(cfg.RunMode))
	ui.PrintField("Expected privilege", cfg.ExpectedPrivilege)
}

// --- small flag helpers ---------------------------------------------------

func mustBool(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}
func mustString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}
func mustStringSlice(cmd *cobra.Command, name string) []string {
	v, _ := cmd.Flags().GetStringSlice(name)
	return v
}
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
