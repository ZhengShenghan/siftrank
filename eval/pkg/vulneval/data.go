package vulneval

import (
	"encoding/json"
	"fmt"
	"os"
)

// Function represents a decompiled binary function for evaluation.
type Function struct {
	Name       string   `json:"func"`
	Binary     string   `json:"binary"`
	CVE        string   `json:"cve"`
	CWEIDs     []string `json:"cwe_ids"`
	Decompiled string   `json:"decompiled"`
	Source     string   `json:"source"` // "cve" or "patched"
	PairIdx    int      `json:"pair_idx"`

	// Ground truth label
	Vulnerable *bool `json:"vulnerable,omitempty"`

	// Populated at runtime for "wrong" CWE experiment
	WrongCWEIDs []string `json:"-"`
}

// CWEDescription holds the official name and description for a CWE.
type CWEDescription struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// LoadFunctions reads a JSON array of Function objects from a file.
func LoadFunctions(path string) ([]Function, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading data file: %w", err)
	}

	var functions []Function
	if err := json.Unmarshal(data, &functions); err != nil {
		return nil, fmt.Errorf("parsing data file: %w", err)
	}

	if len(functions) == 0 {
		return nil, fmt.Errorf("data file contains no functions")
	}

	return functions, nil
}

// LoadCWEDescriptions reads the CWE descriptions JSON file.
func LoadCWEDescriptions(path string) (map[string]CWEDescription, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CWE descriptions: %w", err)
	}

	var descs map[string]CWEDescription
	if err := json.Unmarshal(data, &descs); err != nil {
		return nil, fmt.Errorf("parsing CWE descriptions: %w", err)
	}

	return descs, nil
}

// LoadCWEWrongMapping reads the wrong-CWE mapping JSON file.
func LoadCWEWrongMapping(path string) (map[string]string, error) {
	if path == "" {
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading wrong-CWE mapping: %w", err)
	}

	var mapping map[string]string
	if err := json.Unmarshal(data, &mapping); err != nil {
		return nil, fmt.Errorf("parsing wrong-CWE mapping: %w", err)
	}

	return mapping, nil
}

// ApplyWrongCWEs populates WrongCWEIDs on each function using the mapping.
func ApplyWrongCWEs(functions []Function, mapping map[string]string) {
	for i := range functions {
		wrong := make([]string, 0, len(functions[i].CWEIDs))
		for _, cwe := range functions[i].CWEIDs {
			if w, ok := mapping[cwe]; ok {
				wrong = append(wrong, w)
			}
		}
		functions[i].WrongCWEIDs = wrong
	}
}
