// Package ui centralizes everything about how chaosify looks on the terminal.
//
// There are two things exported here:
//
//   - A single brand Palette plus a set of ready-made lipgloss styles, so the
//     rest of the codebase never hardcodes a hex value. Import "internal/ui"
//     and use ui.Success / ui.Error / ui.Title instead of building styles inline.
//   - A huh form Theme (FormTheme) derived from that same Palette, so the
//     interactive prompts in prompts.go match the standalone output.
//
// Keeping the palette in one place means a rebrand is a one-file change.
package ui

import (
	"image/color"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// Palette is the chaosify brand color set. Every style in the application is
// built from these named colors — change them here and the whole UI follows.
// (In lipgloss v2, lipgloss.Color is a constructor that returns a color.Color.)
var Palette = struct {
	Primary   color.Color // Headings, primary emphasis.
	Secondary color.Color // Selection cursors, accents.
	Success   color.Color // Confirmations, "connected" states.
	Warning   color.Color // Cautions, dry-run reminders.
	Danger    color.Color // Errors, destructive confirmations.
	Info      color.Color // Neutral informational text.
	Muted     color.Color // Descriptions, placeholders, hints.
	Text      color.Color // Default foreground.
	Inverted  color.Color // Text drawn on a colored background.
}{
	Primary:   lipgloss.Color("#7D56F4"),
	Secondary: lipgloss.Color("#F780E2"),
	Success:   lipgloss.Color("#02BA84"),
	Warning:   lipgloss.Color("#F5A623"),
	Danger:    lipgloss.Color("#FF4672"),
	Info:      lipgloss.Color("#4EA5D9"),
	Muted:     lipgloss.Color("#6C6C6C"),
	Text:      lipgloss.Color("#FAFAFA"),
	Inverted:  lipgloss.Color("#FAFAFA"),
}

// Ready-made lipgloss styles. Use these for standalone (non-form) output such
// as banners, status lines, and the final configuration echo.
var (
	// Banner is the bold, filled header used at the top of a phase.
	Banner = lipgloss.NewStyle().
		Bold(true).
		Foreground(Palette.Inverted).
		Background(Palette.Primary).
		Padding(0, 1)

	// Title styles a section heading.
	Title = lipgloss.NewStyle().Bold(true).Foreground(Palette.Primary)

	// Success / Warn / Fail / Info style single-line status messages.
	Success = lipgloss.NewStyle().Foreground(Palette.Success)
	Warn    = lipgloss.NewStyle().Foreground(Palette.Warning)
	Fail    = lipgloss.NewStyle().Foreground(Palette.Danger)
	Info    = lipgloss.NewStyle().Foreground(Palette.Info)

	// Label / Value style the two halves of an echoed "key: value" line.
	Label = lipgloss.NewStyle().Foreground(Palette.Muted)
	Value = lipgloss.NewStyle().Foreground(Palette.Text).Bold(true)
)

// FormTheme returns a huh theme built from the chaosify Palette. It is passed to
// every interactive prompt so forms are visually consistent with the styles
// above. It is a huh.ThemeFunc, so huh re-evaluates it for light/dark terminals.
func FormTheme() huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		// Start from huh's base styles and only override colors we care about.
		s := huh.ThemeBase(isDark)

		s.Focused.Title = s.Focused.Title.Foreground(Palette.Primary).Bold(true)
		s.Focused.NoteTitle = s.Focused.NoteTitle.Foreground(Palette.Primary).Bold(true)
		s.Focused.Description = s.Focused.Description.Foreground(Palette.Muted)
		s.Focused.Base = s.Focused.Base.BorderForeground(Palette.Primary)
		s.Focused.Card = s.Focused.Base

		s.Focused.SelectSelector = s.Focused.SelectSelector.Foreground(Palette.Secondary)
		s.Focused.MultiSelectSelector = s.Focused.MultiSelectSelector.Foreground(Palette.Secondary)
		s.Focused.NextIndicator = s.Focused.NextIndicator.Foreground(Palette.Secondary)
		s.Focused.PrevIndicator = s.Focused.PrevIndicator.Foreground(Palette.Secondary)

		s.Focused.SelectedOption = s.Focused.SelectedOption.Foreground(Palette.Success)
		s.Focused.SelectedPrefix = lipgloss.NewStyle().Foreground(Palette.Success).SetString("✓ ")
		s.Focused.UnselectedPrefix = lipgloss.NewStyle().Foreground(Palette.Muted).SetString("• ")

		s.Focused.ErrorIndicator = s.Focused.ErrorIndicator.Foreground(Palette.Danger)
		s.Focused.ErrorMessage = s.Focused.ErrorMessage.Foreground(Palette.Danger)

		s.Focused.FocusedButton = s.Focused.FocusedButton.
			Foreground(Palette.Inverted).Background(Palette.Primary)
		s.Focused.Next = s.Focused.FocusedButton
		s.Focused.BlurredButton = s.Focused.BlurredButton.Foreground(Palette.Muted)

		s.Focused.TextInput.Prompt = s.Focused.TextInput.Prompt.Foreground(Palette.Secondary)
		s.Focused.TextInput.Cursor = s.Focused.TextInput.Cursor.Foreground(Palette.Success)
		s.Focused.TextInput.Placeholder = s.Focused.TextInput.Placeholder.Foreground(Palette.Muted)

		// Blurred fields inherit the focused look but with a hidden border so the
		// layout does not jump as focus moves.
		s.Blurred = s.Focused
		s.Blurred.Base = s.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
		s.Blurred.Card = s.Blurred.Base

		return s
	})
}
