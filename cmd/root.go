/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>

*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"

	initcmd "github.com/aahan-pat/chaosify/cmd/init"
	reconcmd "github.com/aahan-pat/chaosify/cmd/recon"
)

// NewRootCmd builds the base command and attaches all subcommands. Each
// subcommand lives in its own package and exposes a New() constructor, so the
// wiring is all here rather than spread across package-level init() functions.
func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "chaosify",
		Short: "A brief description of your application",
		Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
		// Uncomment the following line if your bare application
		// has an action associated with it:
		// Run: func(cmd *cobra.Command, args []string) { },
	}

	rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

	rootCmd.AddCommand(initcmd.New())
	rootCmd.AddCommand(reconcmd.New())

	return rootCmd
}

// Execute builds the root command and runs it. Called by main.main().
func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
