package vulneval

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/noperator/siftrank/pkg/siftrank"
	"github.com/openai/openai-go"
)

// RunEval executes the vulnerability classification evaluation.
func RunEval(ctx context.Context, cfg *EvalConfig) error {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Create LLM provider
	provider, err := siftrank.NewOpenAIProvider(siftrank.OpenAIConfig{
		APIKey:   cfg.APIKey,
		Model:    openai.ChatModel(cfg.Model),
		BaseURL:  cfg.BaseURL,
		Encoding: cfg.Encoding,
		Effort:   cfg.Effort,
		Logger:   logger,
	})
	if err != nil {
		return fmt.Errorf("creating LLM provider: %w", err)
	}

	// Load functions
	functions, err := LoadFunctions(cfg.DataFile)
	if err != nil {
		return fmt.Errorf("loading functions: %w", err)
	}

	// Load CWE descriptions (for "specific" and "wrong" modes)
	cweDescs, err := LoadCWEDescriptions(cfg.CWEDescFile)
	if err != nil {
		return fmt.Errorf("loading CWE descriptions: %w", err)
	}
	if cweDescs == nil {
		cweDescs = make(map[string]CWEDescription)
	}

	// Load and apply wrong-CWE mapping (for "wrong" mode)
	if cfg.VulnType == "wrong" {
		wrongMap, err := LoadCWEWrongMapping(cfg.CWEWrongMapFile)
		if err != nil {
			return fmt.Errorf("loading wrong-CWE mapping: %w", err)
		}
		if wrongMap == nil {
			return fmt.Errorf("cwe_wrong_map_file is required for vuln_type=wrong")
		}
		ApplyWrongCWEs(functions, wrongMap)
	}

	// Filter out functions without CWE mapping for "specific" and "wrong" modes
	if cfg.VulnType == "specific" || cfg.VulnType == "wrong" {
		filtered := make([]Function, 0, len(functions))
		for _, fn := range functions {
			if cfg.VulnType == "specific" && len(fn.CWEIDs) > 0 {
				filtered = append(filtered, fn)
			} else if cfg.VulnType == "wrong" && len(fn.WrongCWEIDs) > 0 {
				filtered = append(filtered, fn)
			}
		}
		logger.Info("Filtered functions without CWE mapping",
			"before", len(functions), "after", len(filtered))
		functions = filtered
	}

	logger.Info("Starting evaluation",
		"model", cfg.Model,
		"functions", len(functions),
		"concurrency", cfg.Concurrency,
		"vuln_type", cfg.VulnType,
	)

	// Generate structured output schema
	schema := siftrank.GenerateSchema[VulnClassification]()

	// Set up concurrency
	sem := make(chan struct{}, cfg.Concurrency)
	var mu sync.Mutex
	results := make([]FunctionResult, 0, len(functions))
	var completed atomic.Int64

	startTime := time.Now()
	total := len(functions)

	var wg sync.WaitGroup
	for i, fn := range functions {
		wg.Add(1)
		sem <- struct{}{} // acquire

		go func(idx int, fn Function) {
			defer wg.Done()
			defer func() { <-sem }() // release

			result := classifyFunction(ctx, provider, schema, fn, cfg, cweDescs)
			n := completed.Add(1)

			mu.Lock()
			results = append(results, result)
			mu.Unlock()

			logger.Info("Classified function",
				"progress", fmt.Sprintf("%d/%d", n, total),
				"func", fn.Name,
				"predicted", result.Predicted,
				"ground_truth", result.GroundTruth,
				"latency_ms", result.LatencyMS,
				"input_tokens", result.InputTokens,
				"output_tokens", result.OutputTokens,
				"reasoning_tokens", result.ReasoningTokens,
				"error", result.Error,
			)
		}(i, fn)
	}

	wg.Wait()
	endTime := time.Now()

	// Compute and write results
	summary := ComputeSummary(*cfg, results, startTime, endTime)
	if err := WriteResults(cfg.OutputDir, *cfg, results, summary); err != nil {
		return fmt.Errorf("writing results: %w", err)
	}

	// Print summary to stdout
	printSummary(summary)

	return nil
}

// classifyFunction runs classification for a single function.
func classifyFunction(ctx context.Context, provider *siftrank.OpenAIProvider, schema interface{}, fn Function, cfg *EvalConfig, cweDescs map[string]CWEDescription) FunctionResult {
	prompt := BuildPrompt(fn, cfg.VulnType, cweDescs)

	opts := &siftrank.CompletionOptions{
		Schema:      schema,
		Temperature: cfg.Temperature,
	}

	start := time.Now()
	raw, err := provider.Complete(ctx, prompt, opts)
	latency := time.Since(start)

	result := FunctionResult{
		FuncName:    fn.Name,
		Binary:      fn.Binary,
		CVE:         fn.CVE,
		Source:      fn.Source,
		LatencyMS:   latency.Milliseconds(),
		GroundTruth: fn.Vulnerable,
	}

	if err != nil {
		result.Error = true
		result.Reasoning = fmt.Sprintf("error: %v", err)
		return result
	}

	// Parse structured response
	var classification VulnClassification
	if err := json.Unmarshal([]byte(raw), &classification); err != nil {
		result.Error = true
		result.Reasoning = fmt.Sprintf("parse error: %v (raw: %s)", err, raw)
		return result
	}

	result.Predicted = classification.Vulnerable
	result.PredVulnType = classification.VulnType
	result.Reasoning = classification.Reasoning
	result.InputTokens = opts.Usage.InputTokens
	result.OutputTokens = opts.Usage.OutputTokens
	result.ReasoningTokens = opts.Usage.ReasoningTokens
	result.ModelUsed = opts.ModelUsed
	result.RequestID = opts.RequestID

	return result
}

func printSummary(s RunSummary) {
	fmt.Println("\n========================================")
	fmt.Println("       Evaluation Summary")
	fmt.Println("========================================")
	fmt.Printf("Experiment:     %s\n", s.Config.ExperimentName)
	fmt.Printf("Model:          %s\n", s.Config.Model)
	fmt.Printf("Vuln type:      %s\n", s.Config.VulnType)
	fmt.Printf("Concurrency:    %d\n", s.Config.Concurrency)

	fmt.Println("\n--- Volume ---")
	fmt.Printf("Total functions: %d\n", s.TotalFunctions)
	fmt.Printf("API calls:       %d\n", s.TotalAPICalls)
	fmt.Printf("Errors:          %d\n", s.TotalErrors)

	fmt.Println("\n--- Timing ---")
	fmt.Printf("Wall clock:      %.2fs\n", s.WallClockSec)
	fmt.Printf("Throughput:      %.1f req/min\n", s.ThroughputRPM)
	fmt.Printf("Latency mean:    %.0fms\n", s.Latency.MeanMS)
	fmt.Printf("Latency median:  %.0fms\n", s.Latency.MedianMS)
	fmt.Printf("Latency p5:      %.0fms\n", s.Latency.P5MS)
	fmt.Printf("Latency p95:     %.0fms\n", s.Latency.P95MS)
	fmt.Printf("Latency min:     %dms\n", s.Latency.MinMS)
	fmt.Printf("Latency max:     %dms\n", s.Latency.MaxMS)
	fmt.Printf("Latency stddev:  %.0fms\n", s.Latency.StdDevMS)

	fmt.Println("\n--- Tokens ---")
	fmt.Printf("Input total:     %d\n", s.TotalInputTokens)
	fmt.Printf("Output total:    %d\n", s.TotalOutputTokens)
	if s.TotalReasoningTokens > 0 {
		fmt.Printf("Reasoning total: %d\n", s.TotalReasoningTokens)
	}
	fmt.Printf("All tokens:      %d\n", s.TotalTokens)
	fmt.Printf("Tokens/min:      %.0f\n", s.ThroughputTPM)
	fmt.Printf("Input  (mean/median/min/max): %.0f / %.0f / %d / %d\n",
		s.InputTokenStats.Mean, s.InputTokenStats.Median,
		s.InputTokenStats.Min, s.InputTokenStats.Max)
	fmt.Printf("Output (mean/median/min/max): %.0f / %.0f / %d / %d\n",
		s.OutputTokenStats.Mean, s.OutputTokenStats.Median,
		s.OutputTokenStats.Min, s.OutputTokenStats.Max)

	if s.Accuracy != nil {
		fmt.Println("\n--- Classification ---")
		fmt.Printf("Accuracy:        %.4f\n", *s.Accuracy)
		if s.BalancedAcc != nil {
			fmt.Printf("Balanced Acc:    %.4f\n", *s.BalancedAcc)
		}
		if s.Precision != nil {
			fmt.Printf("Precision:       %.4f\n", *s.Precision)
		}
		if s.Recall != nil {
			fmt.Printf("Recall:          %.4f\n", *s.Recall)
		}
		if s.F1 != nil {
			fmt.Printf("F1:              %.4f\n", *s.F1)
		}
		if s.Specificity != nil {
			fmt.Printf("Specificity:     %.4f\n", *s.Specificity)
		}
		if s.MCC != nil {
			fmt.Printf("MCC:             %.4f\n", *s.MCC)
		}
		fmt.Printf("\nConfusion Matrix:\n")
		fmt.Printf("                 Predicted\n")
		fmt.Printf("                 Vuln    Safe\n")
		fmt.Printf("  Actual Vuln    %-7d %d\n", *s.TruePositives, *s.FalseNegatives)
		fmt.Printf("  Actual Safe    %-7d %d\n", *s.FalsePositives, *s.TrueNegatives)
	}
	fmt.Println("========================================")
}
