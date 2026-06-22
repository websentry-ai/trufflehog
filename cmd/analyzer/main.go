package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors/tokenizer"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/defaults"
)

const (
	unverifiedScore           = 0.9
	defaultGenericSecretScore = 0.8
	maxBodyBytes              = 1 << 20
	scanTimeout               = 3 * time.Second
)

type ctxKey string

const reqIDKey ctxKey = "reqID"

func reqIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(reqIDKey).(string); ok && v != "" {
		return v
	}
	return "-"
}

func parseGenericSecretScore(raw string) (float64, error) {
	if raw == "" {
		return defaultGenericSecretScore, nil
	}
	score, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(score) || math.IsInf(score, 0) || score < 0.0 || score > 1.0 {
		return 0, fmt.Errorf("score %q out of range [0.0, 1.0]", raw)
	}
	return score, nil
}

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
	raw        string
}

type scanner struct {
	core               *ahocorasick.Core
	detectors          int
	genericSecretScore float64
	mode               suppressionMode
}

func liveness(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]string{"status": "ok"})
}

func (s *scanner) readiness(w http.ResponseWriter, _ *http.Request) {
	if s.core == nil || s.detectors == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]string{"status": "not ready"})
		return
	}
	writeJSON(w, map[string]any{"status": "ok", "detectors": s.detectors})
}

func main() {
	_ = godotenv.Load()
	apiKey := os.Getenv("TRUFFLEHOG_API_KEY")
	if apiKey == "" {
		log.Fatal("TRUFFLEHOG_API_KEY is required")
	}

	port := 8080
	if raw := os.Getenv("PORT"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 65535 {
			log.Fatal("invalid PORT: must be an integer in 1-65535")
		}
		port = n
	}

	dets := defaults.DefaultDetectors()
	genericScore := defaultGenericSecretScore
	if genericSecretsEnabled() {
		score, err := parseGenericSecretScore(os.Getenv("GENERIC_SECRET_SCORE"))
		if err != nil {
			log.Fatalf("invalid GENERIC_SECRET_SCORE: %v", err)
		}
		genericScore = score
		d, err := customdetectors.NewGenericSecret()
		if err != nil {
			log.Fatalf("generic-secret detector init failed: %v", err)
		}
		dets = append(dets, d)
		log.Printf("generic-secret detector ENABLED (score=%.2f)", genericScore)

		dbURI, err := customdetectors.NewDBConnectionURI()
		if err != nil {
			log.Fatalf("db-connection-uri detector init failed: %v", err)
		}
		dets = append(dets, dbURI)
		log.Printf("db-connection-uri detector ENABLED (score=%.2f)", genericScore)

		privKey, err := customdetectors.NewPrivateKey()
		if err != nil {
			log.Fatalf("private-key detector init failed: %v", err)
		}
		dets = append(dets, privKey)
		log.Printf("private-key detector ENABLED (score=%.2f)", unverifiedScore)
	}
	if entropyProximityEnabled() {
		threshold, err := customdetectors.ParseEntropyThreshold(os.Getenv("ENTROPY_THRESHOLD"))
		if err != nil {
			log.Fatalf("invalid ENTROPY_THRESHOLD: %v", err)
		}
		tokenizerName := os.Getenv("ANALYZER_TOKENIZER")
		tok, err := tokenizer.Select(tokenizerName)
		if err != nil {
			log.Fatalf("invalid ANALYZER_TOKENIZER: %v", err)
		}
		dets = append(dets, customdetectors.NewEntropyProximityWithTokenizer(threshold, tok))
		log.Printf("entropy-proximity detector ENABLED (threshold=%.1f, tokenizer=%q)", threshold, tokenizerName)
	}
	mode := parseSuppressionMode(os.Getenv("FP_SUPPRESSION_MODE"))
	s := &scanner{core: ahocorasick.NewAhoCorasickCore(dets), detectors: len(dets), genericSecretScore: genericScore, mode: mode}
	log.Printf("trufflehog-analyzer ready: %d detectors, fp_suppression=%s", s.detectors, mode)

	mux := http.NewServeMux()
	mux.HandleFunc("/analyze", s.analyzeHandler(apiKey))
	mux.HandleFunc("/health", liveness)
	mux.HandleFunc("/readyz", s.readiness)
	mux.Handle("/metrics", promhttp.Handler())

	addr := ":" + strconv.Itoa(port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func (s *scanner) analyzeHandler(apiKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		status := http.StatusOK
		defer func() {
			analyzeRequestDuration.Observe(time.Since(start).Seconds())
			analyzeRequestsTotal.WithLabelValues(strconv.Itoa(status)).Inc()
		}()

		if r.Method != http.MethodPost {
			status = http.StatusMethodNotAllowed
			http.Error(w, "method not allowed", status)
			return
		}
		if !authorized(r, apiKey) {
			status = http.StatusUnauthorized
			http.Error(w, "unauthorized", status)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Text == "" {
			status = http.StatusBadRequest
			writeJSON(w, []analyzeResult{})
			return
		}
		scannedBytes.Observe(float64(len(req.Text)))

		reqID := r.Header.Get("X-Request-Id")
		ctx, cancel := context.WithTimeout(r.Context(), scanTimeout)
		defer cancel()
		ctx = context.WithValue(ctx, reqIDKey, reqID)
		results := s.scan(ctx, []byte(req.Text), req.ScoreThreshold)
		log.Printf("scan complete req=%s bytes=%d findings=%d", reqIDFrom(ctx), len(req.Text), len(results))
		writeJSON(w, results)
	}
}

func (s *scanner) scan(ctx context.Context, data []byte, threshold float64) []analyzeResult {
	start := time.Now()
	defer func() { scanDuration.Observe(time.Since(start).Seconds()) }()

	reqID := reqIDFrom(ctx)
	out := []analyzeResult{}
	for _, match := range s.core.FindDetectorMatches(data) {
		found, err := match.FromData(ctx, false, data)
		if err != nil {
			detectorErrorsTotal.WithLabelValues(match.Key.Type().String()).Inc()
			log.Printf("scan detector_error req=%s detector=%s bytes=%d err=%v", reqID, match.Key.Type().String(), len(data), err)
			continue
		}
		for _, res := range found {
			score := unverifiedScore
			entity := res.DetectorType.String()
			if isGenericDetectorName(res.DetectorName) {
				score = s.genericSecretScore
			}
			if res.DetectorName != "" {
				entity = res.DetectorName
			}
			if score < threshold {
				continue
			}
			if isObviousPlaceholder(string(res.Raw)) {
				placeholdersSuppressedTotal.WithLabelValues(entity).Inc()
				continue
			}
			start, end, ok := offsets(data, res.Raw)
			if !ok {
				log.Printf("scan offset_miss req=%s entity=%s raw_len=%d bytes=%d", reqID, entity, len(res.Raw), len(data))
				continue
			}
			out = append(out, analyzeResult{
				EntityType: entity,
				Start:      start,
				End:        end,
				Score:      score,
				Source:     "trufflehog",
				raw:        string(res.Raw),
			})
		}
	}
	deduped := s.applySuppression(ctx, dedupeOverlapping(out), data)
	for _, res := range deduped {
		detectionsTotal.WithLabelValues(res.EntityType).Inc()
	}
	return deduped
}

func dedupeOverlapping(in []analyzeResult) []analyzeResult {
	if len(in) <= 1 {
		return in
	}
	ranked := make([]analyzeResult, len(in))
	copy(ranked, in)
	sort.SliceStable(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if ra, rb := entityRank(a.EntityType), entityRank(b.EntityType); ra != rb {
			return ra < rb
		}
		if wa, wb := a.End-a.Start, b.End-b.Start; wa != wb {
			return wa > wb
		}
		return a.Start < b.Start
	})

	kept := make([]analyzeResult, 0, len(ranked))
	for _, f := range ranked {
		overlaps := false
		for _, k := range kept {
			if f.Start < k.End && k.Start < f.End {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, f)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	return kept
}

func entityRank(name string) int {
	switch name {
	case customdetectors.EntropyName:
		return 2
	case customdetectors.GenericSecretName:
		return 1
	default:
		return 0
	}
}

func isGenericDetectorName(name string) bool {
	return name == customdetectors.GenericSecretName ||
		name == customdetectors.DBConnectionURIName ||
		name == customdetectors.EntropyName
}

func genericSecretsEnabled() bool {
	log.Printf("ENABLE_GENERIC_SECRETS: %s", os.Getenv("ENABLE_GENERIC_SECRETS"))
	switch os.Getenv("ENABLE_GENERIC_SECRETS") {
	case "true", "1":
		return true
	default:
		return false
	}
}

func entropyProximityEnabled() bool {
	log.Printf("Entropy proximity enabled: %s", os.Getenv("ENABLE_ENTROPY_PROXIMITY"))
	switch os.Getenv("ENABLE_ENTROPY_PROXIMITY") {
	case "true", "1":
		return true
	default:
		return false
	}
}

var placeholderMarkers = []string{
	"example", "redacted", "placeholder", "changeme", "change-me",
	"do-not-use", "do_not_use", "your_", "your-", "yourkey", "yourtoken", "dummy", "sample",
	"replace", "xxxx",
}

func isObviousPlaceholder(raw string) bool {
	lower := strings.ToLower(raw)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return hasLongRepeatRun(raw, 8)
}

func hasLongRepeatRun(s string, n int) bool {
	run := 1
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			run++
			if run >= n {
				return true
			}
			continue
		}
		run = 1
	}
	return false
}

func offsets(data, raw []byte) (int, int, bool) {
	if len(raw) == 0 {
		return 0, 0, false
	}
	i := bytes.Index(data, raw)
	if i < 0 {
		return 0, 0, false
	}
	start := utf8.RuneCount(data[:i])
	end := start + utf8.RuneCount(raw)
	return start, end, true
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
