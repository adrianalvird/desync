// pkg/detector/detector.go

package detector

import (
	"context"
	"desync/pkg/session"
)

// Finding represents a single detection result.
type Finding struct {
	DetectorName string
	VictimURL    string
	Confidence   float64 // 0.0 to 1.0
	Detail       string
	Evidence     map[string]interface{} // additional evidence
}

// Detector is the interface each smuggling detection technique must implement.
type Detector interface {
	Name() string
	// Detect runs the detection against a session (with its baseline) and victim URLs.
	// It returns findings for suspicious victims.
	Detect(ctx context.Context, sess *session.Session, baselineURL string, victimURLs []string) ([]Finding, error)
}