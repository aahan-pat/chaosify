/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/

package initcmd

// This file holds the offline authorization logic for Phase 1. It is
// deliberately free of any UI or Kubernetes dependency: it only parses and
// validates the authorization artifact. This keeps the "hard gate" rules in one
// testable place, separate from how they are collected or displayed.

import (
	"fmt"
	"strings"
	"time"

	"github.com/aahan-pat/chaosify/internal/types"
)

// DateLayout is the accepted format for the valid-from / valid-until inputs.
const DateLayout = "2006-01-02"

// ParseDate parses a YYYY-MM-DD string into a time.Time, returning a clear error
// suitable for use as a huh field validator.
func ParseDate(s string) (time.Time, error) {
	t, err := time.Parse(DateLayout, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, fmt.Errorf("date must be in YYYY-MM-DD format")
	}
	return t, nil
}

// ValidateDateString is a convenience validator for text prompts: it accepts any
// parseable date. Window ordering and currency are checked separately by
// ValidateWindow once both dates are known.
func ValidateDateString(s string) error {
	_, err := ParseDate(s)
	return err
}

// NonEmpty is a reusable validator that rejects blank/whitespace input. Used for
// the engagement ID and sign-off reference.
func NonEmpty(field string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", field)
		}
		return nil
	}
}

// ValidateWindow enforces the authorization window rules against the reference
// time now:
//
//   - valid-from must be strictly before valid-until;
//   - now must fall within [valid-from, valid-until].
//
// This is the hard gate: if it returns an error, no connection may be attempted.
func ValidateWindow(from, until, now time.Time) error {
	if !from.Before(until) {
		return fmt.Errorf("valid-from (%s) must be before valid-until (%s)",
			from.Format(DateLayout), until.Format(DateLayout))
	}
	if now.Before(from) {
		return fmt.Errorf("engagement is not authorized yet; it begins %s",
			from.Format(DateLayout))
	}
	// until is inclusive of the whole day, so compare against end-of-day.
	endOfDay := until.Add(24*time.Hour - time.Nanosecond)
	if now.After(endOfDay) {
		return fmt.Errorf("engagement authorization expired on %s",
			until.Format(DateLayout))
	}
	return nil
}

// Validate runs all authorization checks against the given reference time and is
// the single entry point Phase 1 uses to decide whether the gate opens.
func Validate(a types.Authorization, now time.Time) error {
	if strings.TrimSpace(a.EngagementID) == "" {
		return fmt.Errorf("engagement ID is required")
	}
	if strings.TrimSpace(a.SignOffRef) == "" {
		return fmt.Errorf("sign-off reference is required")
	}
	return ValidateWindow(a.ValidFrom, a.ValidUntil, now)
}
