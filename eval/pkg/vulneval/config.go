package vulneval

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// EvalConfig holds all configuration for a vulnerability evaluation run.
type EvalConfig struct {
	// LLM connection
	Model       string   `yaml:"model" json:"model"`
	BaseURL     string   `yaml:"base_url" json:"base_url"`
	APIKey      string   `yaml:"api_key" json:"-"`
	APIKeyCMD   string   `yaml:"api_key_cmd" json:"-"`
	Encoding    string   `yaml:"encoding" json:"encoding"`
	Effort      string   `yaml:"effort" json:"effort"`
	Temperature *float64 `yaml:"temperature" json:"temperature"`

	// Eval parameters
	Concurrency     int    `yaml:"concurrency" json:"concurrency"`
	DataFile        string `yaml:"data_file" json:"data_file"`
	OutputDir       string `yaml:"output_dir" json:"output_dir"`
	VulnType        string `yaml:"vuln_type" json:"vuln_type"`
	CWEDescFile     string `yaml:"cwe_desc_file" json:"cwe_desc_file,omitempty"`
	CWEWrongMapFile string `yaml:"cwe_wrong_map_file" json:"cwe_wrong_map_file,omitempty"`

	// Metadata
	ExperimentName string `yaml:"experiment_name" json:"experiment_name"`
	Notes          string `yaml:"notes" json:"notes"`
}

// LoadConfig reads an EvalConfig from a YAML file.
func LoadConfig(path string) (*EvalConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	var cfg EvalConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	// Resolve api_key_cmd if api_key is empty
	if cfg.APIKey == "" && cfg.APIKeyCMD != "" {
		out, err := exec.Command("sh", "-c", cfg.APIKeyCMD).Output()
		if err != nil {
			return nil, fmt.Errorf("executing api_key_cmd: %w", err)
		}
		cfg.APIKey = strings.TrimSpace(string(out))
	}

	// Apply defaults
	if cfg.Encoding == "" {
		cfg.Encoding = "o200k_base"
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 10
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "results"
	}
	if cfg.VulnType == "" {
		cfg.VulnType = "any"
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://openrouter.ai/api/v1"
	}

	return &cfg, nil
}

// Validate checks that the config has all required fields.
func (c *EvalConfig) Validate() error {
	if c.Model == "" {
		return fmt.Errorf("model is required")
	}
	if c.APIKey == "" {
		return fmt.Errorf("api_key or api_key_cmd is required")
	}
	if c.DataFile == "" {
		return fmt.Errorf("data_file is required")
	}
	return nil
}
