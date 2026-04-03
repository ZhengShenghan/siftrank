package vulneval

import (
	"fmt"
	"strings"
)

// VulnClassification is the structured response schema for vulnerability classification.
type VulnClassification struct {
	Vulnerable bool   `json:"vulnerable" jsonschema_description:"true if the function contains a vulnerability, false otherwise"`
	VulnType   string `json:"vuln_type" jsonschema_description:"type of vulnerability if found, empty string otherwise"`
	Reasoning  string `json:"reasoning" jsonschema_description:"brief explanation of the classification decision"`
}

// BuildPrompt constructs the classification prompt for a single function.
//
// vulnType modes:
//   - "any": asks about any vulnerability
//   - "specific": asks about the function's actual CWE (from cwe_ids)
//   - "wrong": asks about a deliberately wrong CWE (from wrong_cwe_ids)
//   - "CWE-XXX": direct CWE override
func BuildPrompt(fn Function, vulnType string, cweDescs map[string]CWEDescription) string {
	vulnClause := "any vulnerability"
	switch vulnType {
	case "specific":
		if len(fn.CWEIDs) > 0 {
			vulnClause = formatCWEClause(fn.CWEIDs, cweDescs)
		}
	case "wrong":
		if len(fn.WrongCWEIDs) > 0 {
			vulnClause = formatCWEClause(fn.WrongCWEIDs, cweDescs)
		}
	case "", "any":
		// default: "any vulnerability"
	default:
		// Direct CWE override (e.g., vulnType="CWE-190")
		vulnClause = formatCWEClause([]string{vulnType}, cweDescs)
	}

	return fmt.Sprintf(`You are a binary security analyst. Analyze the following decompiled function for vulnerabilities.

Function: %s
Binary: %s

%s

Classify whether this function contains %s.`, fn.Name, fn.Binary, fn.Decompiled, vulnClause)
}

// formatCWEClause builds a description like:
// "a CWE-190 (Integer Overflow or Wraparound: The product performs a calculation that can produce an integer overflow...) vulnerability"
func formatCWEClause(cweIDs []string, cweDescs map[string]CWEDescription) string {
	parts := make([]string, 0, len(cweIDs))
	for _, id := range cweIDs {
		if desc, ok := cweDescs[id]; ok && desc.Name != "" {
			detail := desc.Name
			if desc.Description != "" {
				detail += ": " + desc.Description
			}
			parts = append(parts, fmt.Sprintf("%s (%s)", id, detail))
		} else {
			parts = append(parts, id)
		}
	}
	return fmt.Sprintf("a %s vulnerability", strings.Join(parts, " / "))
}
