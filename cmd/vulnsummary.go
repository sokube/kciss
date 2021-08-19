package main

// A summary of vulnerabilities found (for an image, or a namespace)
type VulnSummary struct {
	Critical, High, Medium, Low uint32
}

// Accumulate vulnerabilities
func (v VulnSummary) Add(b VulnSummary) VulnSummary {
	return VulnSummary{v.Critical + b.Critical, v.High + b.High, v.Medium + b.Medium, v.Low + b.Low}
}

// Summary when image occurs multiple times
func (v VulnSummary) Mult(occurences uint32) VulnSummary {
	return VulnSummary{v.Critical * occurences, v.High * occurences, v.Medium * occurences, v.Low * occurences}
}

// Return a unitary summary for 1 vulnerability of a given severity
func SummaryForSeverity(sev string) VulnSummary {
	var v VulnSummary
	switch {
	case sev == "CRITICAL":
		v.Critical = 1
	case sev == "HIGH":
		v.High = 1
	case sev == "MEDIUM":
		v.Medium = 1
	case sev == "LOW":
		v.Low = 1
	}
	return v
}
