//pkg/detector/modules/tete.go

package modules

import (
	"context"
	"fmt"

	"desync/pkg/detector"
	"desync/pkg/session"
)

type TETEDetector struct{}

func (d *TETEDetector) Name() string { return "TE.TE" }

func (d *TETEDetector) Detect(ctx context.Context, sess *session.Session,
	baselineURL string, victimURLs []string) ([]detector.Finding, error) {

	baseline := sess.GetBaseline()
	if baseline == nil {
		var err error
		baseline, err = sess.FingerprintBaseline(ctx, baselineURL, 3)
		if err != nil {
			return nil, err
		}
	}

	probes := []struct {
		name string
		req  string
	}{
		{"double_te", "POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n"},
		{"te_with_spaces", "POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding : chunked\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n"},
		{"te_obfuscation", "POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding:\tchunked\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n"},
		{"te_0_chunk", "POST %s HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n"},
	}

	var findings []detector.Finding
	for _, probe := range probes {
		probeData := []byte(fmt.Sprintf(probe.req, getPath(baselineURL), extractHost(baselineURL)))
		resps, durations, err := sess.SendProbeAndVictims(ctx, probeData, victimURLs)
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
					DetectorName: d.Name() + "/" + probe.name,
					VictimURL:    vurl,
					Confidence:   confidence,
					Detail:       fmt.Sprintf("%s (timing anomaly=%v)", detail, timingAnomaly),
				})
			}
		}
	}
	return findings, nil
}