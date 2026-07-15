package main

import (
	"bytes"
	"fmt"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
)

type CheckRequest struct {
	ImageDigest       string `json:"image_digest"`
	Namespace         string `json:"namespace"`
	PodTemplateHash   string `json:"pod_template_hash"`
}

type CheckResponse struct {
	OverallStatus string `json:"overall_status"`
	CheckedDigest string `json:"checked_digest"`
	Checks        ChecksBlock `json:"checks"`
}

type ChecksBlock struct {
	Trivy CheckResult `json:"trivy"`
}

type CheckResult struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

// --- Structs matching Trivy's real JSON output shape ---

type TrivyReport struct {
	Results []TrivyResult `json:"Results"`
}

type TrivyResult struct {
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

type TrivyVulnerability struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	Severity         string `json:"Severity"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
}

// runTrivyScan shells out to the real trivy binary and returns the parsed report.
func runTrivyScan(image string) (*TrivyReport, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", "--skip-version-check", image)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("trivy exec failed: %v, stderr: %s", err, stderr.String())
	}

	var report TrivyReport
	err = json.Unmarshal(stdout.Bytes(), &report)
	if err != nil {
		return nil, fmt.Errorf("failed to parse trivy output: %v", err)
	}

	return &report, nil
}

// evaluateTrivyResult counts CRITICAL/HIGH findings and decides pass/fail.
func evaluateTrivyResult(report *TrivyReport) CheckResult {
	criticalCount := 0
	highCount := 0

	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity == "CRITICAL" {
				criticalCount++
			} else if vuln.Severity == "HIGH" {
				highCount++
			}
		}
	}
	if criticalCount > 0 {
		return CheckResult{
			Status: "fail",
			Reason: "found critical vulnerabilities",
		}
	}

	return CheckResult{
		Status: "pass",
		Reason: "no critical vulnerabilities found",
	}
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	var req CheckRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	log.Printf("Received check request: digest=%s namespace=%s pod-hash=%s",
		req.ImageDigest, req.Namespace, req.PodTemplateHash)

	report, err := runTrivyScan(req.ImageDigest)
	if err != nil {
		log.Printf("Trivy scan failed: %v", err)
		http.Error(w, "trivy scan failed", http.StatusInternalServerError)
		return
	}

	trivyResult := evaluateTrivyResult(report)

	response := CheckResponse{
		OverallStatus: trivyResult.Status,
		CheckedDigest: req.ImageDigest,
		Checks: ChecksBlock{
			Trivy: trivyResult,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/check", checkHandler)
	log.Println("analysis-runner listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
