package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

const (
	unverifiedScore = 0.9
	maxBodyBytes    = 1 << 20
	scanTimeout     = 3 * time.Second
)

type analyzeRequest struct {
	Text           string  `json:"text"`
	ScoreThreshold float64 `json:"score_threshold"`
}

type analyzeResult struct {
	EntityType string  `json:"entity_type"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
	Source     string  `json:"source"`
}

type scanner struct {
	core *ahocorasick.Core
}

func main() {
	_ = godotenv.Load()
	apiKey := os.Getenv("TRUFFLEHOG_API_KEY")
	if apiKey == "" {
		log.Fatal("TRUFFLEHOG_API_KEY is required")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dets := defaults.DefaultDetectors()
	s := &scanner{core: ahocorasick.NewAhoCorasickCore(dets)}
	log.Printf("trufflehog-analyzer ready: %d detectors", len(dets))

	mux := http.NewServeMux()
	mux.HandleFunc("/analyze", s.analyzeHandler(apiKey))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]string{"status": "ok"})
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("listening on :%s", port)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func (s *scanner) analyzeHandler(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !authorized(r, apiKey) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
			writeJSON(w, []analyzeResult{})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
		defer cancel()
		results := s.scan(ctx, []byte(req.Text), req.ScoreThreshold)
		log.Printf("/analyze: scanned %d bytes, %d secret(s)", len(req.Text), len(results))
		writeJSON(w, results)
	}
}

func (s *scanner) scan(ctx context.Context, data []byte, threshold float64) []analyzeResult {
	out := []analyzeResult{}
	for _, match := range s.core.FindDetectorMatches(data) {
		found, err := match.FromData(ctx, false, data)
		if err != nil {
			log.Printf("detector %s error: %v", match.Key.Type().String(), err)
			continue
		}
		if unverifiedScore < threshold {
			continue
		}
		for _, res := range found {
			start, end, ok := offsets(data, res.Raw)
			if !ok {
				log.Printf("could not locate %s match, skipping", match.Key.Type().String())
				continue
			}
			out = append(out, analyzeResult{
				EntityType: res.DetectorType.String(),
				Start:      start,
				End:        end,
				Score:      unverifiedScore,
				Source:     "trufflehog",
			})
		}
	}
	return out
}

func offsets(data, raw []byte) (int, int, bool) {
	if len(raw) == 0 {
		return 0, 0, false
	}
	if i := bytes.Index(data, raw); i >= 0 {
		return i, i + len(raw), true
	}
	return 0, 0, false
}

func authorized(r *http.Request, apiKey string) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || h[:len(prefix)] != prefix {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(h[len(prefix):]), []byte(apiKey)) == 1
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
