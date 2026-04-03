package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/noperator/siftrank/eval/pkg/vulneval"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: vulneval --config <config.yaml>")
		os.Exit(1)
	}

	cfg, err := vulneval.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading config: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if err := vulneval.RunEval(ctx, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "evaluation failed: %v\n", err)
		os.Exit(1)
	}
}
