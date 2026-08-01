package ui

import (
	"fmt"
	"os"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// ---------------------------------------------------------------------------
// Standalone output helpers
//
// These print themed, single-line messages. They are used for banners, status
// updates, and the final configuration echo — anything that is not an
// interactive prompt.
// ---------------------------------------------------------------------------

// PrintBanner prints a full-width phase header.
func PrintBanner(text string) {
	fmt.Println()
	lipgloss.Println(Banner.Render(text))
	fmt.Println()
}

// PrintTitle prints a section heading.
func PrintTitle(text string) { lipgloss.Println(Title.Render(text)) }

// PrintSuccess, PrintWarn, PrintError, and PrintInfo print a status line with a
// leading glyph in the matching color.
func PrintSuccess(format string, a ...any) {
	lipgloss.Println(Success.Render("✓ " + fmt.Sprintf(format, a...)))
}
func PrintWarn(format string, a ...any) {
	lipgloss.Println(Warn.Render("! " + fmt.Sprintf(format, a...)))
}
func PrintError(format string, a ...any) {
	lipgloss.Println(Fail.Render("✗ " + fmt.Sprintf(format, a...)))
}
func PrintInfo(format string, a ...any) {
	lipgloss.Println(Info.Render("• " + fmt.Sprintf(format, a...)))
}

// PrintField echoes a resolved "label: value" pair (e.g. "Cluster: prod-eu").
func PrintField(label, value string) {
	lipgloss.Println(Label.Render(label+": ") + Value.Render(value))
}

// ---------------------------------------------------------------------------
// Provided-else-prompt helpers
//
// Every helper follows the same contract, which is the heart of the design:
//
//	if provided { validate the given value and return it, no prompt }
//	else        { run the interactive huh field and return the answer }
//
// This makes non-interactive CI (flags supplied → provided == true) and
// interactive init (nothing supplied → provided == false) the exact same code
// path at the call site. Callers pass provided as cmd.Flags().Changed("flag").
//
// When a value is missing AND the process is not attached to a terminal, the
// helpers fail fast rather than hang, so CI never blocks on a hidden prompt.
// ---------------------------------------------------------------------------

// ErrNonInteractive is returned when a value is required, was not provided, and
// there is no terminal to prompt on.
var ErrNonInteractive = fmt.Errorf("value not provided and no interactive terminal available")

// interactive reports whether stdin is a real terminal we can prompt on.
func interactive() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && (fi.Mode()&os.ModeCharDevice) != 0
}

// TextInput returns provided (after optional validation) when it is set,
// otherwise prompts for a single line of text. Set password to mask input.
func TextInput(provided bool, value, title, description, placeholder string, password bool, validate func(string) error) (string, error) {
	if provided {
		if validate != nil {
			if err := validate(value); err != nil {
				return "", err
			}
		}
		return value, nil
	}
	if !interactive() {
		return "", fmt.Errorf("%q: %w", title, ErrNonInteractive)
	}

	result := value
	field := huh.NewInput().
		Title(title).
		Description(description).
		Placeholder(placeholder).
		Password(password).
		Validate(validate).
		Value(&result)
	if err := field.WithTheme(FormTheme()).Run(); err != nil {
		return "", err
	}
	return result, nil
}

// Select returns provided when set, otherwise presents options as a single-choice
// list — no blind typing. The provided value, if any, is validated against the
// option set so a bad flag fails loudly.
func Select(provided bool, value, title, description string, options []string) (string, error) {
	if provided {
		for _, o := range options {
			if o == value {
				return value, nil
			}
		}
		return "", fmt.Errorf("%q is not one of the available options for %q", value, title)
	}
	if !interactive() {
		return "", fmt.Errorf("%q: %w", title, ErrNonInteractive)
	}

	result := value
	field := huh.NewSelect[string]().
		Title(title).
		Description(description).
		Options(huh.NewOptions(options...)...).
		Value(&result)
	if err := field.WithTheme(FormTheme()).Run(); err != nil {
		return "", err
	}
	return result, nil
}

// MultiSelect returns provided when set, otherwise presents options as a
// checklist. preselect names the options that should start checked (e.g. "sweep
// all" pre-checks every namespace). The provided slice is validated against the
// option set.
func MultiSelect(provided bool, value []string, title, description string, options, preselect []string) ([]string, error) {
	if provided {
		valid := make(map[string]bool, len(options))
		for _, o := range options {
			valid[o] = true
		}
		for _, v := range value {
			if !valid[v] {
				return nil, fmt.Errorf("%q is not one of the available options for %q", v, title)
			}
		}
		return value, nil
	}
	if !interactive() {
		return nil, fmt.Errorf("%q: %w", title, ErrNonInteractive)
	}

	checked := make(map[string]bool, len(preselect))
	for _, p := range preselect {
		checked[p] = true
	}
	opts := make([]huh.Option[string], 0, len(options))
	for _, o := range options {
		opts = append(opts, huh.NewOption(o, o).Selected(checked[o]))
	}

	result := append([]string(nil), value...)
	field := huh.NewMultiSelect[string]().
		Title(title).
		Description(description).
		Options(opts...).
		Value(&result)
	if err := field.WithTheme(FormTheme()).Run(); err != nil {
		return nil, err
	}
	return result, nil
}

// Confirm returns provided when set, otherwise asks a yes/no question. Use it for
// gates such as enabling active mode or skipping TLS verification.
func Confirm(provided bool, value bool, title, description, affirmative, negative string) (bool, error) {
	if provided {
		return value, nil
	}
	if !interactive() {
		return false, fmt.Errorf("%q: %w", title, ErrNonInteractive)
	}

	result := value
	field := huh.NewConfirm().
		Title(title).
		Description(description).
		Affirmative(affirmative).
		Negative(negative).
		Value(&result)
	if err := field.WithTheme(FormTheme()).Run(); err != nil {
		return false, err
	}
	return result, nil
}

// FilePick returns provided when set, otherwise opens a file browser. currentDir
// seeds the browser's starting directory.
func FilePick(provided bool, value, title, description, currentDir string) (string, error) {
	if provided {
		return value, nil
	}
	if !interactive() {
		return "", fmt.Errorf("%q: %w", title, ErrNonInteractive)
	}

	result := value
	field := huh.NewFilePicker().
		Title(title).
		Description(description).
		CurrentDirectory(currentDir).
		ShowHidden(true).
		Value(&result)
	if err := field.WithTheme(FormTheme()).Run(); err != nil {
		return "", err
	}
	return result, nil
}
