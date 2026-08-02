package main

import (
	"bytes"
	"fmt"
	"encoding/json"
	"log/slog"
	"net/http"
	"os/exec"
	"time"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

var logger = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type AllowlistEntry struct {
	CVE        string `yaml:"cve"`
	Reason     string `yaml:"reason"`
	ApprovedBy string `yaml:"approved_by"`
	Expires    string `yaml:"expires"`
}

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
	Kyverno CheckResult `json:"kyverno"`
	Cosign CheckResult `json:"cosign"`
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
	Status           string `json:"Status"`
}

// --- Structs matching Kyverno PolicyReport JSON output shape ---

type PolicyReport struct {
	Results []PolicyReportResult `json:"results"`
}

type PolicyReportResult struct {
	Policy  string `json:"policy"`
	Rule    string `json:"rule"`
	Result  string `json:"result"`
	Message string `json:"message"`
}

var (
	checkResultsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "securerollout_check_results_total",
			Help: "Total number of check results, labeled by tool and outcome",
		},
		[]string{"tool", "status"}, // tool: trivy|kyverno|cosign, status: pass|fail
	)

	checkDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "securerollout_check_duration_seconds",
			Help:    "Time taken to complete a full /check request (all three tools)",
			Buckets: prometheus.DefBuckets, // default buckets: .005 to 10 seconds
		},
	)
)

func init() {
	prometheus.MustRegister(checkResultsTotal)
	prometheus.MustRegister(checkDurationSeconds)
}

// loadAllowlist reads the accepted-CVEs ConfigMap from the cluster and
// returns only the entries that haven't expired.
func loadAllowlist(namespace string) ([]AllowlistEntry, error) {
	cmd := exec.Command("kubectl", "get", "configmap", "security-gate-allowlist",
		"-n", namespace,
		"-o", "jsonpath={.data.accepted-cves\\.yml}")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// No ConfigMap found is NOT a fatal error — it just means an empty allowlist.
		// This matters for fail-closed correctness: if we can't read the allowlist,
		// we should NOT silently treat everything as accepted. Returning an empty
		// list here means every CRITICAL still fails the gate, which is the safe default.
		return []AllowlistEntry{}, nil
	}

	var entries []AllowlistEntry
	err = yaml.Unmarshal(stdout.Bytes(), &entries)
	if err != nil {
		return nil, fmt.Errorf("failed to parse allowlist: %v", err)
	}

	// Filter out expired entries
	var active []AllowlistEntry
	now := time.Now()
	for _, entry := range entries {
		expiry, err := time.Parse("2006-01-02", entry.Expires)
		if err != nil || expiry.After(now) {
			// If expiry date is malformed, fail closed: treat as NOT active
			// (don't accept the CVE) rather than assume it's still valid.
			if err == nil {
				active = append(active, entry)
			}
		}
	}

	return active, nil
}

func refreshTrivyDB() {
	cmd := exec.Command("trivy", "image", "--download-db-only", "--skip-version-check")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Fail-closed consideration: don't crash the whole service if this
		// fails (Kyverno/cosign checks are unaffected and should still work).
		// Trivy scans will then correctly fail-closed on their own, since
		// --skip-db-update will error out with no DB present, rather than
		// silently re-attempting a download during a live request.
		logger.Warn("trivy DB refresh at startup failed", "error", err.Error(), "stderr", stderr.String())
		return
	}
	logger.Info("Trivy DB refreshed successfully at startup")
}

// runTrivyScan shells out to the real trivy binary and returns the parsed report.
func runTrivyScan(image string) (*TrivyReport, error) {
	cmd := exec.Command("trivy", "image", "--format", "json", "--skip-version-check","--skip-db-update", image)

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
func evaluateTrivyResult(report *TrivyReport, allowlist []AllowlistEntry) CheckResult {
	var unfixedCritical []TrivyVulnerability // Status: fixed, but not upgraded — genuinely actionable
	var unfixableCritical []TrivyVulnerability // Status: affected/fix_deferred/will_not_fix — no fix exists
	var acceptedCritical []TrivyVulnerability // unfixable, but present on the active allowlist

	allowlistSet := make(map[string]bool)
	for _, entry := range allowlist {
		allowlistSet[entry.CVE] = true
	}

	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			if vuln.Severity != "CRITICAL" {
				continue
			}

			if allowlistSet[vuln.VulnerabilityID] {
				acceptedCritical = append(acceptedCritical, vuln)
				continue
			}

			if vuln.Status == "fixed" {
				unfixedCritical = append(unfixedCritical, vuln)
			} else {
				unfixableCritical = append(unfixableCritical, vuln)
			}
		}
	}

	// Any actionable (fixable, not yet upgraded) CRITICAL fails immediately.
	if len(unfixedCritical) > 0 {
		return CheckResult{
			Status: "fail",
			Reason: fmt.Sprintf("%d actionable CRITICAL CVE(s) found (fix available): %s",
				len(unfixedCritical), unfixedCritical[0].VulnerabilityID),
		}
	}

	// Unfixable CRITICALs that aren't on the allowlist also fail — they require
	// explicit human review and acceptance, not automatic pass-through.
	if len(unfixableCritical) > 0 {
		return CheckResult{
			Status: "fail",
			Reason: fmt.Sprintf("%d CRITICAL CVE(s) with no available fix, not yet reviewed/accepted: %s (add to security-gate-allowlist ConfigMap after review)",
				len(unfixableCritical), unfixableCritical[0].VulnerabilityID),
		}
	}

	reason := "no unaccepted critical vulnerabilities found"
	if len(acceptedCritical) > 0 {
		reason = fmt.Sprintf("%d CRITICAL CVE(s) present but explicitly accepted via allowlist: %s",
			len(acceptedCritical), acceptedCritical[0].VulnerabilityID)
	}

	return CheckResult{
		Status: "pass",
		Reason: reason,
	}
}

// runKyvernoCheck finds the PolicyReport for a pod matching the given
// namespace and pod-template-hash, and evaluates it for failures.
func runKyvernoCheck(namespace string, podTemplateHash string) CheckResult {
	// Find a pod matching this revision's label
	cmd := exec.Command("kubectl", "get", "pods",
		"-n", namespace,
		"-l", "rollouts-pod-template-hash="+podTemplateHash,
		"-o", "jsonpath={.items[0].metadata.name}")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil || stdout.String() == "" {
		return CheckResult{
			Status: "fail",
			Reason: fmt.Sprintf("could not find pod for revision: %v, stderr: %s", err, stderr.String()),
		}
	}
	podName := stdout.String()

	// Kyverno names PolicyReports after the resource they cover, but the
	// simplest reliable lookup is by resource name via label/field selector.
	// For now, fetch all PolicyReports in the namespace and find the one
	// whose resource name matches our pod.
	cmd2 := exec.Command("kubectl", "get", "policyreport",
		"-n", namespace,
		"-o", "json")

	var stdout2, stderr2 bytes.Buffer
	cmd2.Stdout = &stdout2
	cmd2.Stderr = &stderr2

	err = cmd2.Run()
	if err != nil {
		return CheckResult{
			Status: "fail",
			Reason: fmt.Sprintf("could not fetch policy reports: %v, stderr: %s", err, stderr2.String()),
		}
	}

	var reportList struct {
		Items []struct {
			Metadata struct {
				OwnerReferences []struct {
					Kind string `json:"kind"`
					Name string `json:"name"`
				} `json:"ownerReferences"`
			} `json:"metadata"`
			Results []PolicyReportResult `json:"results"`
		} `json:"items"`
	}

	err = json.Unmarshal(stdout2.Bytes(), &reportList)
	if err != nil {
		return CheckResult{
			Status: "fail",
			Reason: fmt.Sprintf("failed to parse policy reports: %v", err),
		}
	}

	for _, item := range reportList.Items {
		for _, owner := range item.Metadata.OwnerReferences {
			if owner.Kind == "Pod" && owner.Name == podName {
				for _, result := range item.Results {
					if result.Result == "fail" {
						return CheckResult{
							Status: "fail",
							Reason: result.Message,
						}
					}
				}
			}
		}
	}

	return CheckResult{
		Status: "pass",
		Reason: "no policy violations found",
	}
}

// runCosignVerify shells out to cosign to verify a keyless signature
// exists and is valid for the given image reference.
func runCosignVerify(imageRef string) CheckResult {
	cmd := exec.Command("cosign", "verify",
		imageRef,
		"--certificate-identity-regexp", ".*",
		"--certificate-oidc-issuer-regexp", ".*")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return CheckResult{
			Status: "fail",
			Reason: fmt.Sprintf("signature verification failed: %s", stderr.String()),
		}
	}

	return CheckResult{
		Status: "pass",
		Reason: "signature verified against Rekor transparency log",
	}
}

func checkHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func(){
		checkDurationSeconds.Observe(time.Since(start).Seconds())
	}()
	var req CheckRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	logger.Info("check request received",
		"image_digest", req.ImageDigest,
		"namespace", req.Namespace,
		"pod_template_hash", req.PodTemplateHash,
	)

	report, err := runTrivyScan(req.ImageDigest)
	var trivyResult CheckResult
	if err != nil {
		logger.Error("Trivy scan errored","error", err.Error())
		trivyResult = CheckResult{Status: "fail", Reason: fmt.Sprintf("trivy check errored: %v", err)}
	} else {
		allowlist, allowErr := loadAllowlist(req.Namespace)
		if allowErr != nil {
			logger.Warn("allowlist load failed", "error", allowErr.Error())
		}
		trivyResult = evaluateTrivyResult(report, allowlist)
	}
	logger.Info("trivy check result", "status", trivyResult.Status, "reason", trivyResult.Reason)
	checkResultsTotal.WithLabelValues("trivy", trivyResult.Status).Inc()
	
	kyvernoResult := runKyvernoCheck(req.Namespace, req.PodTemplateHash)
	logger.Info("kyverno check result", "status", kyvernoResult.Status, "reason", kyvernoResult.Reason)
	checkResultsTotal.WithLabelValues("kyverno", kyvernoResult.Status).Inc()
	
	cosignResult := runCosignVerify(req.ImageDigest)
	logger.Info("cosign check result", "status", cosignResult.Status, "reason", cosignResult.Reason)
	checkResultsTotal.WithLabelValues("cosign", cosignResult.Status).Inc()

	overallStatus := "pass"
	if trivyResult.Status == "fail" || kyvernoResult.Status == "fail" || cosignResult.Status== "fail"  {
		overallStatus = "fail"
	}

	logger.Info("check complete",
		"overall_status", overallStatus,
		"image_digest", req.ImageDigest,
		"duration_seconds", time.Since(start).Seconds(),
	)

	response := CheckResponse{
		OverallStatus: overallStatus,
		CheckedDigest: req.ImageDigest,
		Checks: ChecksBlock{
			Trivy:   trivyResult,
			Kyverno: kyvernoResult,
			Cosign: cosignResult,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	refreshTrivyDB()
	http.HandleFunc("/check", checkHandler)
	http.Handle("/metrics", promhttp.Handler())
	logger.Info("analysis-runner listening", "port", 8081)
	if err := http.ListenAndServe(":8081", nil); err != nil {
		logger.Error("server failed", "error", err.Error())
		os.Exit(1)
	}
}
