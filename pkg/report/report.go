//pkg/report/report.go

package report

import (
	"fmt"
//	"os"

	"desync/pkg/detector"
)

// PrintFindings outputs findings to stdout.
func PrintFindings(findings []detector.Finding) {
	if len(findings) == 0 {
		fmt.Println("No request smuggling vulnerabilities detected.")
		return
	}
	fmt.Printf("=== Desync Detection Report (%d finding(s)) ===\n", len(findings))
	for _, f := range findings {
		fmt.Printf("[%s] Victim: %s, Confidence: %.2f\n", f.DetectorName, f.VictimURL, f.Confidence)
		fmt.Printf("  Detail: %s\n", f.Detail)
	}
}