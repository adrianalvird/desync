// pkg/detector/base.go

package detector

import (
	"net/http"
	"time"

	"desync/pkg/session"
)

// TimingAnomaly checks if a duration is significantly longer than the baseline.
func TimingAnomaly(dur time.Duration, baseline *session.BaselineResult) bool {
	if baseline == nil || len(baseline.TimingSamples) == 0 {
		return false
	}
	diff := dur - baseline.AvgTime
	if diff < 0 {
		diff = -diff
	}
	// Anomaly if > 3 standard deviations OR absolute difference > 500ms
	if baseline.StdDevTime > 0 && diff > 3*baseline.StdDevTime {
		return true
	}
	if diff > 500*time.Millisecond {
		return true
	}
	return false
}

// ResponseDiff checks if the victim response differs from the baseline.
// Since the victim body was already drained, it compares only status code
// and Content-Length header.
func ResponseDiff(victimResp *http.Response, baseline *session.BaselineResult) (bool, string) {
	if baseline == nil {
		return false, ""
	}
	if victimResp.StatusCode != baseline.StatusCode {
		return true, "status " + http.StatusText(victimResp.StatusCode) +
			" vs baseline " + http.StatusText(baseline.StatusCode)
	}
	// Compare approximate body length (Content-Length header vs actual baseline body length)
	victimCL := victimResp.ContentLength
	baselineCL := int64(len(baseline.Body))
	if victimCL != baselineCL && baselineCL > 0 {
		return true, "content-length mismatch"
	}
	return false, ""
}

// ConfidenceHeuristic combines multiple signals into a 0..1 score.
func ConfidenceHeuristic(timingAnomaly bool, responseDiff bool, additionalSignals float64) float64 {
	base := 0.0
	if timingAnomaly {
		base += 0.4
	}
	if responseDiff {
		base += 0.5
	}
	base += additionalSignals
	if base > 1.0 {
		base = 1.0
	}
	return base
}