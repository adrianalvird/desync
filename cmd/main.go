// cmd/main.go

package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"

	"desync/pkg/config"
	"desync/pkg/detector"
	"desync/pkg/detector/modules"
	"desync/pkg/report"
	"desync/pkg/runner"
	"desync/pkg/target"
)

func main() {
	targetFile := flag.String("target", "target.json", "JSON file with target URLs")
	concurrency := flag.Int("c", 5, "number of concurrent host scans")
	flag.Parse()

	// Load target entries
	entries, err := config.LoadTargets(*targetFile)
	if err != nil {
		log.Fatalf("failed to load targets: %v", err)
	}

	// Group by host and assign baseline/victim roles
	groups, err := target.GroupByHost(entries, nil)
	if err != nil {
		log.Fatalf("grouping targets: %v", err)
	}
	log.Printf("loaded %d host group(s)", len(groups))

	// Register detectors
	detectors := []detector.Detector{
		&modules.CLTEDetector{},
		&modules.TECLDetector{},
		&modules.TETEDetector{},
	}

	// Context that cancels on Ctrl+C
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		<-c
		log.Println("interrupt received, shutting down...")
		cancel()
	}()

	// Create runner and execute
	r := runner.NewRunner(groups, detectors)
	r.Concurrency = *concurrency
	findings := r.Run(ctx)

	// Print results
	report.PrintFindings(findings)
}