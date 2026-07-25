package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

// Version is set at build time via -ldflags, defaults to "dev" for local runs.
var Version = "dev"

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": Version,
	})
}

func rootHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<html><body style='background-color:#4CAF50;font-family:sans-serif;text-align:center;padding-top:100px;'><h1>target-app version: %s</h1></body></html>", Version)
}

func main() {
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", rootHandler)
	log.Printf("target-app (version %s) listening on :8080", Version)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
