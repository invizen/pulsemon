package main

import (
	"errors"
	"fmt"
)

// sensorSpec is the validated, default-applied form of a sensor's tunable
// fields. Every sensor write path (POST, PATCH, clone) funnels through
// applyDefaults + validate (or clamp), so the ranges, defaults, and
// cross-field rules live in ONE place (the old code had the
// same ranges, defaults, and type==""→icmp normalization in 5+ places).
type sensorSpec struct {
	Name      string
	Target    string
	Type      string // "icmp" | "http" | "tcp" (normalized)
	Tags      []string
	IntervalS int
	TimeoutMS int
	LossWarn  int
	DownAfter int
	SpikeMult int
}

// sensorBounds is the single source of truth for each numeric sensor field's
// [min, max] range. validate, clamp, and validateSensorRange all derive from
// it, so a bound change is one edit. (The old code carried the ranges in all
// three, and the error text hardcoded "interval_s must be 5-3600" even though
// the code used minIntervalS — the table makes the message track the bound.)
var sensorBounds = map[string][2]int{
	"interval_s": {minIntervalS, 3600},
	"timeout_ms": {100, 30000},
	"loss_warn":  {1, 100},
	"down_after": {1, 100},
	"spike_mult": {2, 10},
}

// sensorBound returns a field's [min, max], or ok=false for an unknown field.
func sensorBound(field string) ([2]int, bool) {
	b, ok := sensorBounds[field]
	return b, ok
}

// applyDefaults fills zero-valued fields with their defaults. Called on
// the POST path (new sensors). PATCH and clone apply per-field.
func (s *sensorSpec) applyDefaults() {
	if s.Type == "" {
		s.Type = "icmp"
	}
	if s.IntervalS <= 0 {
		s.IntervalS = 60
	}
	if s.TimeoutMS <= 0 {
		s.TimeoutMS = 1000
	}
	if s.LossWarn <= 0 {
		s.LossWarn = 25
	}
	if s.DownAfter <= 0 {
		s.DownAfter = 2
	}
	if s.SpikeMult <= 0 {
		s.SpikeMult = 5
	}
}

// validate checks all ranges, cross-field rules, and format constraints.
// Returns a user-facing error message for the first violation, or nil.
func (s *sensorSpec) validate() error {
	if s.Name == "" || s.Target == "" {
		return errors.New("name and target are required")
	}
	if !validSensorName(s.Name) {
		return errors.New("name must be 1-60 characters and may not contain quotes, angle brackets, backslash, or control characters")
	}
	if err := s.validateCrossField(); err != nil {
		return err
	}
	for _, f := range []struct {
		field string
		value int
	}{
		{"interval_s", s.IntervalS},
		{"timeout_ms", s.TimeoutMS},
		{"loss_warn", s.LossWarn},
		{"down_after", s.DownAfter},
		{"spike_mult", s.SpikeMult},
	} {
		if b, ok := sensorBound(f.field); ok && (f.value < b[0] || f.value > b[1]) {
			return fmt.Errorf("%s must be %d-%d", f.field, b[0], b[1])
		}
	}
	return nil
}

// crossFieldError ties a client-facing validation message to the PATCH
// sentinel that stands for the same rule (review 2026-11-11). The PATCH
// path maps validateCrossField failures onto the errPatch* sentinels for
// its outer errors.Is switch; it used to re-derive that mapping from
// substrings of the message ("URL" / "timeout" / "down_after"), so a
// wording tweak — or a target validation message that happens to contain
// one of those words — silently mis-routed the 400. The rule's code now
// travels INSIDE the error; every caller matches it with errors.Is, and
// Error() keeps the exact detailed text POST /api/sensors renders.
type crossFieldError struct {
	msg  string
	code error
}

func (e *crossFieldError) Error() string { return e.msg }
func (e *crossFieldError) Unwrap() error { return e.code }

// validateCrossField checks the cross-field rules: target format for the
// probe type, and timeout vs interval. Called by validate() and by the
// PATCH in-tx path (which overlays request fields on current DB values
// before calling it). Every rejection carries its sentinel (crossFieldError).
func (s *sensorSpec) validateCrossField() error {
	if s.Type == "http" {
		if !validURL(s.Target) {
			return &crossFieldError{"target must be an http:// or https:// URL (e.g. https://example.com/health)", errPatchTargetNotURL}
		}
	} else if s.Type == "tcp" {
		if !validTCPTarget(s.Target) {
			// TCP and ICMP target failures share the TargetInvalid sentinel
			// — same fall-through the old mapping's default branch produced.
			return &crossFieldError{"target must be host:port with an explicit port 1-65535 (e.g. 10.0.0.5:5432)", errPatchTargetInvalid}
		}
	} else if !validTarget(s.Target) {
		return &crossFieldError{"target must be an IPv4 address or hostname", errPatchTargetInvalid}
	}
	if s.TimeoutMS > s.IntervalS*1000 {
		return &crossFieldError{"timeout_ms must not exceed interval_s*1000", errPatchTimeoutExceedsInterval}
	}
	// down_after × interval_s beyond the 24h probe-retention window can never
	// accumulate down_after consecutive losses (purgeOld keeps only 24h of
	// probes, so the max observable run is 24h/interval_s). A 100%-dead sensor
	// would then sit in warning forever and never reach error — and warnings
	// are never alerted. Reject the combination at write time.
	if int64(s.DownAfter)*int64(s.IntervalS) > retentionSeconds {
		return &crossFieldError{"down_after × interval_s must not exceed 24h (probe retention)", errPatchDownAfterExceedsRetention}
	}
	return nil
}

// clamp brings every field into its valid range. Called on the clone path:
// a legacy source row may carry out-of-range values that the API floors
// were added after. Unlike validate, clamp never errors — it adjusts.
func (s *sensorSpec) clamp() {
	if s.Type == "" {
		s.Type = "icmp"
	}
	s.IntervalS = clampToBound(s.IntervalS, "interval_s")
	s.TimeoutMS = clampToBound(s.TimeoutMS, "timeout_ms")
	s.LossWarn = clampToBound(s.LossWarn, "loss_warn")
	s.DownAfter = clampToBound(s.DownAfter, "down_after")
	s.SpikeMult = clampToBound(s.SpikeMult, "spike_mult")
	// Cross-field: a probe timeout longer than the interval means two
	// probes can never complete back-to-back. Clamp the timeout down.
	if s.TimeoutMS > s.IntervalS*1000 {
		s.TimeoutMS = s.IntervalS * 1000
	}
	// Cross-field: down_after × interval_s beyond the 24h retention window
	// can never reach down_after consecutive losses, so a dead sensor would
	// sit in warning forever and never alert. Floor down_after to what fits
	// the retention window (clone path: adjust, don't reject).
	if maxDown := retentionSeconds / int64(s.IntervalS); int64(s.DownAfter) > maxDown {
		s.DownAfter = int(maxDown)
	}
}

// clampToBound floors/ceils v into a field's [min, max] from sensorBounds.
func clampToBound(v int, field string) int {
	b, ok := sensorBound(field)
	if !ok {
		return v
	}
	if v < b[0] {
		return b[0]
	}
	if v > b[1] {
		return b[1]
	}
	return v
}

// validateSensorRange checks a single numeric field's range (the PATCH
// path: only the fields the request supplies are validated). Returns a
// user-facing error message, or nil.
func validateSensorRange(field string, value int) error {
	b, ok := sensorBound(field)
	if !ok {
		return nil
	}
	if value < b[0] || value > b[1] {
		return fmt.Errorf("%s must be %d-%d", field, b[0], b[1])
	}
	return nil
}
