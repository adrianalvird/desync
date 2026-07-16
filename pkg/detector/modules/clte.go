//pkg/detector/modules/clte.go

package modules

import (
	"context"
	"fmt"

	"desync/pkg/detector"
	"desync/pkg/session"
)

type CLTEDetector struct{}

func (d *CLTEDetector) Name() string { return "CL.TE" }

func (d *CLTEDetector) Detect(ctx context.Context, sess *session.Session,
	baselineURL string, victimURLs []string) ([]detector.Finding, error) {

	baseline := sess.GetBaseline()
	if baseline == nil {
		var err error
		baseline, err = sess.FingerprintBaseline(ctx, baselineURL, 3)
		if err != nil {
			return nil, fmt.Errorf("baseline fingerprint: %w", err)
		}
	}

	probeTemplate := "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n"

	var findings []detector.Finding
	clValues := []int{5, 6, 10, 20}

	for _, cl := range clValues {
		probe := []byte(fmt.Sprintf(probeTemplate, getPath(baselineURL), extractHost(baselineURL), cl))
		resps, durations, err := sess.SendProbeAndVictims(ctx, probe, victimURLs)
		if err != nil {
			continue
		}
		if len(resps) != len(victimURLs) {
			continue
		}
		for i, vurl := range victimURLs {
			vresp := resps[i]
			vdur := durations[i]

			timingAnomaly := detector.TimingAnomaly(vdur, baseline)
			responseDiff, detail := detector.ResponseDiff(vresp, baseline)

			confidence := detector.ConfidenceHeuristic(timingAnomaly, responseDiff, 0)
			if confidence > 0.3 {
				findings = append(findings, detector.Finding{
					DetectorName: d.Name(),
					VictimURL:    vurl,
					Confidence:   confidence,
					Detail:       fmt.Sprintf("%s (timing anomaly=%v, CL=%d)", detail, timingAnomaly, cl),
				})
			}
		}
	}
	return findings, nil
}