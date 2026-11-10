package main

import "errors"

// sensorSpec is the validated, default-applied form of a sensor's tunable
// fields. Every sensor write path (POST, PATCH, clone) funnels through
// applyDefaults + validate (or clamp), so the ranges, defaults, and
// cross-field rules live in ONE place (finding #14: the old code had the
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
	if s.IntervalS < minIntervalS || s.IntervalS > 3600 {
		return errors.New("interval_s must be 5-3600")
	}
	if s.TimeoutMS < 100 || s.TimeoutMS > 30000 {
		return errors.New("timeout_ms must be 100-30000")
	}
	if s.LossWarn < 1 || s.LossWarn > 100 {
		return errors.New("loss_warn must be 1-100")
	}
	if s.DownAfter < 1 || s.DownAfter > 100 {
		return errors.New("down_after must be 1-100")
	}
	if s.SpikeMult < 2 || s.SpikeMult > 10 {
		return errors.New("spike_mult must be 2-10")
	}
	return nil
}

// validateCrossField checks the cross-field rules: target format for the
// probe type, and timeout vs interval. Called by validate() and by the
// PATCH in-tx path (which overlays request fields on current DB values
// before calling it).
func (s *sensorSpec) validateCrossField() error {
	if s.Type == "http" {
		if !validURL(s.Target) {
			return errors.New("target must be an http:// or https:// URL (e.g. https://example.com/health)")
		}
	} else if s.Type == "tcp" {
		if !validTCPTarget(s.Target) {
			return errors.New("target must be host:port with an explicit port 1-65535 (e.g. 10.0.0.5:5432)")
		}
	} else if !validTarget(s.Target) {
		return errors.New("target must be an IPv4 address or hostname")
	}
	if s.TimeoutMS > s.IntervalS*1000 {
		return errors.New("timeout_ms must not exceed interval_s*1000")
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
	if s.IntervalS < minIntervalS {
		s.IntervalS = minIntervalS
	} else if s.IntervalS > 3600 {
		s.IntervalS = 3600
	}
	if s.TimeoutMS < 100 {
		s.TimeoutMS = 100
	} else if s.TimeoutMS > 30000 {
		s.TimeoutMS = 30000
	}
	if s.LossWarn < 1 {
		s.LossWarn = 1
	} else if s.LossWarn > 100 {
		s.LossWarn = 100
	}
	if s.DownAfter < 1 {
		s.DownAfter = 1
	} else if s.DownAfter > 100 {
		s.DownAfter = 100
	}
	if s.SpikeMult < 2 {
		s.SpikeMult = 2
	} else if s.SpikeMult > 10 {
		s.SpikeMult = 10
	}
	// Cross-field: a probe timeout longer than the interval means two
	// probes can never complete back-to-back. Clamp the timeout down.
	if s.TimeoutMS > s.IntervalS*1000 {
		s.TimeoutMS = s.IntervalS * 1000
	}
}

// validateSensorRange checks a single numeric field's range (the PATCH
// path: only the fields the request supplies are validated). Returns a
// user-facing error message, or nil.
func validateSensorRange(field string, value int) error {
	switch field {
	case "interval_s":
		if value < minIntervalS || value > 3600 {
			return errors.New("interval_s must be 5-3600")
		}
	case "timeout_ms":
		if value < 100 || value > 30000 {
			return errors.New("timeout_ms must be 100-30000")
		}
	case "loss_warn":
		if value < 1 || value > 100 {
			return errors.New("loss_warn must be 1-100")
		}
	case "down_after":
		if value < 1 || value > 100 {
			return errors.New("down_after must be 1-100")
		}
	case "spike_mult":
		if value < 2 || value > 10 {
			return errors.New("spike_mult must be 2-10")
		}
	}
	return nil
}
