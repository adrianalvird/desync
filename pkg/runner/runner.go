//pkg/runner/runner.go

package runner

import (
	"context"
//	"fmt"
	"log"
	"sync"
//	"time"

	"desync/pkg/detector"
	"desync/pkg/session"
	"desync/pkg/target"
)

// Runner runs detectors across host groups.
type Runner struct {
	HostGroups []target.HostGroup
	Detectors  []detector.Detector
	Concurrency int
}

// NewRunner creates a new Runner.
func NewRunner(hostGroups []target.HostGroup, detectors []detector.Detector) *Runner {
	return &Runner{
		HostGroups: hostGroups,
		Detectors:  detectors,
		Concurrency: 5,
	}
}

// Run executes scanning and returns all findings.
func (r *Runner) Run(ctx context.Context) []detector.Finding {
	var findings []detector.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, r.Concurrency)
	for _, hg := range r.HostGroups {
		wg.Add(1)
		sem <- struct{}{}
		go func(hg target.HostGroup) {
			defer wg.Done()
			defer func() { <-sem }()

			sess := session.NewSession(hg.Host)
			baselineURL := hg.Baseline.URL.String()
			// Fingerprint baseline once
			_, err := sess.FingerprintBaseline(ctx, baselineURL, 3)
			if err != nil {
				log.Printf("fingerprint %s: %v", hg.Host, err)
				return
			}
			victimURLs := make([]string, len(hg.VictimURLs()))
			for i, v := range hg.VictimURLs() {
				victimURLs[i] = v.URL.String()
			}
			for _, det := range r.Detectors {
				// Respect context
				select {
				case <-ctx.Done():
					return
				default:
				}
				detFindings, err := det.Detect(ctx, sess, baselineURL, victimURLs)
				if err != nil {
					log.Printf("detector %s on %s: %v", det.Name(), hg.Host, err)
					continue
				}
				if len(detFindings) > 0 {
					mu.Lock()
					findings = append(findings, detFindings...)
					mu.Unlock()
				}
			}
		}(hg)
	}
	wg.Wait()
	return findings
}