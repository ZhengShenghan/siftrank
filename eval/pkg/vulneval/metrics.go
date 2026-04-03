package vulneval

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FunctionResult holds the evaluation result for a single function.
type FunctionResult struct {
	FuncName        string `json:"func_name"`
	Binary          string `json:"binary"`
	CVE             string `json:"cve"`
	Source          string `json:"source"` // "cve" or "patched"
	Predicted       bool   `json:"predicted_vulnerable"`
	PredVulnType    string `json:"predicted_vuln_type"`
	Reasoning       string `json:"reasoning"`
	GroundTruth     *bool  `json:"ground_truth,omitempty"`
	InputTokens     int    `json:"input_tokens"`
	OutputTokens    int    `json:"output_tokens"`
	ReasoningTokens int    `json:"reasoning_tokens"`
	LatencyMS       int64  `json:"latency_ms"`
	ModelUsed       string `json:"model_used"`
	RequestID       string `json:"request_id"`
	Error           bool   `json:"error"`
}

// LatencyStats holds latency distribution metrics.
type LatencyStats struct {
	MeanMS   float64 `json:"mean_ms"`
	MedianMS float64 `json:"median_ms"`
	P5MS     float64 `json:"p5_ms"`
	P95MS    float64 `json:"p95_ms"`
	MinMS    int64   `json:"min_ms"`
	MaxMS    int64   `json:"max_ms"`
	StdDevMS float64 `json:"stddev_ms"`
}

// TokenStats holds token usage distribution metrics.
type TokenStats struct {
	Total  int     `json:"total"`
	Mean   float64 `json:"mean"`
	Median float64 `json:"median"`
	Min    int     `json:"min"`
	Max    int     `json:"max"`
}

// RunSummary holds aggregate metrics for an entire evaluation run.
type RunSummary struct {
	// Run metadata
	Config       EvalConfig `json:"config"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      time.Time  `json:"end_time"`
	WallClockSec float64    `json:"wall_clock_sec"`

	// Volume
	TotalFunctions int `json:"total_functions"`
	TotalAPICalls  int `json:"total_api_calls"`
	TotalErrors    int `json:"total_errors"`

	// Token usage
	TotalInputTokens     int        `json:"total_input_tokens"`
	TotalOutputTokens    int        `json:"total_output_tokens"`
	TotalReasoningTokens int        `json:"total_reasoning_tokens"`
	TotalTokens          int        `json:"total_tokens"`
	InputTokenStats      TokenStats `json:"input_token_stats"`
	OutputTokenStats     TokenStats `json:"output_token_stats"`

	// Latency
	Latency        LatencyStats `json:"latency"`
	ThroughputRPM  float64      `json:"throughput_rpm"`  // requests per minute
	ThroughputTPM  float64      `json:"throughput_tpm"`  // tokens per minute

	// Classification metrics (populated only when ground truth is available)
	Accuracy       *float64 `json:"accuracy,omitempty"`
	Precision      *float64 `json:"precision,omitempty"`
	Recall         *float64 `json:"recall,omitempty"`
	F1             *float64 `json:"f1,omitempty"`
	Specificity    *float64 `json:"specificity,omitempty"`
	BalancedAcc    *float64 `json:"balanced_accuracy,omitempty"`
	MCC            *float64 `json:"mcc,omitempty"` // Matthews correlation coefficient
	TruePositives  *int     `json:"true_positives,omitempty"`
	FalsePositives *int     `json:"false_positives,omitempty"`
	TrueNegatives  *int     `json:"true_negatives,omitempty"`
	FalseNegatives *int     `json:"false_negatives,omitempty"`
}

func computeLatencyStats(results []FunctionResult) LatencyStats {
	if len(results) == 0 {
		return LatencyStats{}
	}

	latencies := make([]float64, 0, len(results))
	for _, r := range results {
		latencies = append(latencies, float64(r.LatencyMS))
	}
	sort.Float64s(latencies)

	n := float64(len(latencies))
	sum := 0.0
	for _, l := range latencies {
		sum += l
	}
	mean := sum / n

	// Standard deviation
	sumSq := 0.0
	for _, l := range latencies {
		d := l - mean
		sumSq += d * d
	}
	stddev := math.Sqrt(sumSq / n)

	return LatencyStats{
		MeanMS:   mean,
		MedianMS: percentile(latencies, 0.5),
		P5MS:     percentile(latencies, 0.05),
		P95MS:    percentile(latencies, 0.95),
		MinMS:    int64(latencies[0]),
		MaxMS:    int64(latencies[len(latencies)-1]),
		StdDevMS: stddev,
	}
}

func computeTokenStats(values []int) TokenStats {
	if len(values) == 0 {
		return TokenStats{}
	}

	sorted := make([]float64, len(values))
	total := 0
	for i, v := range values {
		sorted[i] = float64(v)
		total += v
	}
	sort.Float64s(sorted)

	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	return TokenStats{
		Total:  total,
		Mean:   float64(total) / float64(len(values)),
		Median: percentile(sorted, 0.5),
		Min:    min,
		Max:    max,
	}
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := p * float64(len(sorted)-1)
	lower := int(math.Floor(idx))
	upper := int(math.Ceil(idx))
	if lower == upper {
		return sorted[lower]
	}
	frac := idx - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}

// ComputeSummary builds a RunSummary from individual results.
func ComputeSummary(cfg EvalConfig, results []FunctionResult, startTime, endTime time.Time) RunSummary {
	wallClock := endTime.Sub(startTime).Seconds()

	summary := RunSummary{
		Config:         cfg,
		StartTime:      startTime,
		EndTime:        endTime,
		WallClockSec:   wallClock,
		TotalFunctions: len(results),
		TotalAPICalls:  len(results),
	}

	// Count errors
	for _, r := range results {
		if r.Error {
			summary.TotalErrors++
		}
	}

	// Token aggregates
	inputTokens := make([]int, 0, len(results))
	outputTokens := make([]int, 0, len(results))
	for _, r := range results {
		summary.TotalInputTokens += r.InputTokens
		summary.TotalOutputTokens += r.OutputTokens
		summary.TotalReasoningTokens += r.ReasoningTokens
		inputTokens = append(inputTokens, r.InputTokens)
		outputTokens = append(outputTokens, r.OutputTokens)
	}
	summary.TotalTokens = summary.TotalInputTokens + summary.TotalOutputTokens + summary.TotalReasoningTokens
	summary.InputTokenStats = computeTokenStats(inputTokens)
	summary.OutputTokenStats = computeTokenStats(outputTokens)

	// Latency stats
	summary.Latency = computeLatencyStats(results)

	// Throughput
	if wallClock > 0 {
		minutes := wallClock / 60.0
		summary.ThroughputRPM = float64(len(results)) / minutes
		summary.ThroughputTPM = float64(summary.TotalTokens) / minutes
	}

	// Classification metrics
	hasGroundTruth := false
	for _, r := range results {
		if r.GroundTruth != nil {
			hasGroundTruth = true
			break
		}
	}

	if hasGroundTruth {
		tp, fp, tn, fn := 0, 0, 0, 0
		labeled := 0
		for _, r := range results {
			if r.GroundTruth == nil {
				continue
			}
			labeled++
			if *r.GroundTruth && r.Predicted {
				tp++
			} else if !*r.GroundTruth && r.Predicted {
				fp++
			} else if !*r.GroundTruth && !r.Predicted {
				tn++
			} else {
				fn++
			}
		}

		if labeled > 0 {
			acc := float64(tp+tn) / float64(labeled)
			summary.Accuracy = &acc
			summary.TruePositives = &tp
			summary.FalsePositives = &fp
			summary.TrueNegatives = &tn
			summary.FalseNegatives = &fn

			if tp+fp > 0 {
				prec := float64(tp) / float64(tp+fp)
				summary.Precision = &prec
			}
			if tp+fn > 0 {
				rec := float64(tp) / float64(tp+fn)
				summary.Recall = &rec
			}
			if summary.Precision != nil && summary.Recall != nil && (*summary.Precision+*summary.Recall) > 0 {
				f1 := 2 * (*summary.Precision) * (*summary.Recall) / (*summary.Precision + *summary.Recall)
				summary.F1 = &f1
			}
			// Specificity = TN / (TN + FP)
			if tn+fp > 0 {
				spec := float64(tn) / float64(tn+fp)
				summary.Specificity = &spec
			}
			// Balanced accuracy = (sensitivity + specificity) / 2
			if summary.Recall != nil && summary.Specificity != nil {
				ba := (*summary.Recall + *summary.Specificity) / 2
				summary.BalancedAcc = &ba
			}
			// Matthews Correlation Coefficient
			denom := math.Sqrt(float64((tp+fp) * (tp+fn) * (tn+fp) * (tn+fn)))
			if denom > 0 {
				mcc := float64(tp*tn-fp*fn) / denom
				summary.MCC = &mcc
			}
		}
	}

	return summary
}

// sanitizeModel converts a model name like "openai/gpt-5-nano" to "openai_gpt-5-nano" for filenames.
func sanitizeModel(model string) string {
	return strings.ReplaceAll(model, "/", "_")
}

// WriteResults writes JSONL results and a summary JSON file.
func WriteResults(outputDir string, cfg EvalConfig, results []FunctionResult, summary RunSummary) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	ts := summary.StartTime.Format("20060102T150405")
	model := sanitizeModel(cfg.Model)

	// Write JSONL results
	jsonlPath := filepath.Join(outputDir, fmt.Sprintf("%s_%s_results.jsonl", ts, model))
	jsonlFile, err := os.Create(jsonlPath)
	if err != nil {
		return fmt.Errorf("creating results file: %w", err)
	}
	defer jsonlFile.Close()

	enc := json.NewEncoder(jsonlFile)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("writing result: %w", err)
		}
	}

	// Write summary JSON
	summaryPath := filepath.Join(outputDir, fmt.Sprintf("%s_%s_summary.json", ts, model))
	summaryData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling summary: %w", err)
	}
	if err := os.WriteFile(summaryPath, summaryData, 0o644); err != nil {
		return fmt.Errorf("writing summary: %w", err)
	}

	fmt.Printf("Results: %s\n", jsonlPath)
	fmt.Printf("Summary: %s\n", summaryPath)

	return nil
}
