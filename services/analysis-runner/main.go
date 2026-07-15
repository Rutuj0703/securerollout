package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type CheckRequest struct {
	ImageDigest       string `json:"image_digest"`
	Namespace         string `json:"namespace"`
	PodTemplateHash   string `json:"pod_template_hash"`
}

type CheckResponse struct {
	OverallStatus string `json:"overall_status"`
	CheckedDigest string `json:"checked_digest"`
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

	response := CheckResponse{
		OverallStatus: "pass",
		CheckedDigest: req.ImageDigest,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	http.HandleFunc("/check", checkHandler)
	log.Println("analysis-runner listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
