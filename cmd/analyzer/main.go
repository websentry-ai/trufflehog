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
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
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
	EntityType string            `json:"entity_type"`
	Start      int               `json:"start"`
	End        int               `json:"end"`
	Score      float64           `json:"score"`
	Source     string            `json:"source"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	raw        string
}

type scanner struct {
	core *ahocorasick.Core
	// detectors whose match has no length bound, scanned over the whole request
	// rather than per window
	longFormCore       *ahocorasick.Core
	detectors          int
	genericSecretScore float64
	mode               suppressionMode
	vendorMode         suppressionMode
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

	recordBuildInfo()

	cfg, err := scannerConfigFromEnv()
	if err != nil {
		log.Fatalf("invalid scanner config: %v", err)
	}
	s, err := buildScanner(cfg)
	if err != nil {
		log.Fatalf("scanner init failed: %v", err)
	}
	if cfg.genericSecretsEnabled {
		log.Printf("generic-secret + db-connection-uri detectors ENABLED (score=%.2f)", cfg.genericSecretScore)
	}
	if cfg.privateKeyEnabled {
		log.Printf("private-key detector ENABLED (score=%.2f)", unverifiedScore)
	}
	if cfg.entropyProximityEnabled {
		log.Printf("entropy-proximity detector ENABLED (threshold=%.1f, tokenizer=%q)", cfg.entropyThreshold, cfg.tokenizerName)
	}
	log.Printf("trufflehog-analyzer ready: %d detectors, fp_suppression=%s, vendor_structural_suppression=%s", s.detectors, cfg.mode, cfg.vendorMode)

	mux := http.NewServeMux()
	mux.HandleFunc("/analyze", s.analyzeHandler(apiKey))
	mux.HandleFunc("/health", liveness)
	mux.HandleFunc("/readyz", s.readiness)
	mux.Handle("/metrics", promhttp.Handler())

	addr := ":" + strconv.Itoa(port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           accessLog(mux),
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
		inflightRequests.Inc()
		defer func() {
			inflightRequests.Dec()
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

// Upstream's engine feeds detectors 10KB chunks with a 3KB peek, never a whole
// document. Several detectors pair two matches -- a token and a vendor URL, or
// two halves of a credential -- and pair them anywhere in what they are given,
// so handing them a whole request lets unrelated halves hundreds of kilobytes
// apart combine into a finding. Windowing restores the bound upstream assumes.
// Sized to how a credential is actually written down, not to upstream's file
// chunking: a token and the host or second half it belongs with sit in the same
// block, within a few hundred bytes. A wider window only gives unrelated
// components more room to pair. Anything whose match has no length bound is
// scanned separately over the whole request, so this does not truncate it.
const (
	scanWindowSize = 2 * 1024
	scanWindowPeek = 1024
)

func (s *scanner) scan(ctx context.Context, data []byte, threshold float64) []analyzeResult {
	start := time.Now()
	defer func() { scanDuration.Observe(time.Since(start).Seconds()) }()

	// Computed once over the whole request so windowing cannot weaken it.
	var shapes map[string]int
	if s.mode != suppressionOff {
		shapes = documentShapes(data)
	}

	if len(data) <= scanWindowSize+scanWindowPeek {
		return s.record(ctx, s.scanChunk(ctx, data, threshold, 0, shapes))
	}

	var all []analyzeResult
	for off := 0; off < len(data); {
		end := runeBoundary(data, off+scanWindowSize+scanWindowPeek)
		// Offsets are reported in runes, so the window's own start has to be
		// counted the same way before it can be added back.
		all = append(all, s.scanChunk(ctx, data[off:end], threshold, utf8.RuneCount(data[:off]), shapes)...)
		if end == len(data) {
			break
		}
		off = runeBoundary(data, off+scanWindowSize)
	}

	// A PEM block has no length bound and routinely runs past the peek, so a key
	// straddling a boundary would be split. It is a single self-delimiting match
	// with nothing to pair against, so it is scanned over the whole request.
	all = append(all, s.scanLongForm(ctx, data, threshold, shapes)...)
	return s.record(ctx, dedupeIdentical(all))
}

// scanLongForm runs the unbounded-length detectors over the whole request.
func (s *scanner) scanLongForm(ctx context.Context, data []byte, threshold float64, shapes map[string]int) []analyzeResult {
	if s.longFormCore == nil {
		return nil
	}
	saved := s.core
	s.core = s.longFormCore
	defer func() { s.core = saved }()
	return s.scanChunk(ctx, data, threshold, 0, shapes)
}

// runeBoundary moves i forward to the next rune start, so slicing never cuts a
// multibyte sequence -- which would corrupt both the window and the rune count
// used to place its findings.
func runeBoundary(data []byte, i int) int {
	if i >= len(data) {
		return len(data)
	}
	for i < len(data) && !utf8.RuneStart(data[i]) {
		i++
	}
	return i
}

// record emits the per-request metrics once, after every window has been merged.
func (s *scanner) record(ctx context.Context, results []analyzeResult) []analyzeResult {
	for _, res := range results {
		detectionsTotal.WithLabelValues(res.EntityType).Inc()
	}
	findingsPerRequest.Observe(float64(len(results)))
	if ctx.Err() == context.DeadlineExceeded {
		scanTimeoutsTotal.Inc()
	}
	return results
}

// dedupeIdentical drops the repeats that the peek overlap produces.
func dedupeIdentical(in []analyzeResult) []analyzeResult {
	seen := make(map[[2]int]struct{}, len(in))
	out := make([]analyzeResult, 0, len(in))
	for _, r := range in {
		k := [2]int{r.Start, r.End}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

func (s *scanner) scanChunk(ctx context.Context, data []byte, threshold float64, runeBase int, shapes map[string]int) []analyzeResult {
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
				Start:      runeBase + start,
				End:        runeBase + end,
				Score:      score,
				Source:     "trufflehog",
				Metadata:   exposedMetadata(res.ExtraData),
				raw:        string(res.Raw),
			})
		}
	}
	return s.applySuppression(ctx, dedupeOverlapping(out), data, shapes)
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

var exposedMetadataKeys = []string{"support_words", "proximity_score"}

func exposedMetadata(extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return nil
	}
	var out map[string]string
	for _, k := range exposedMetadataKeys {
		if v, ok := extra[k]; ok && v != "" {
			if out == nil {
				out = make(map[string]string, len(exposedMetadataKeys))
			}
			out[k] = v
		}
	}
	return out
}

func isGenericDetectorName(name string) bool {
	return name == customdetectors.GenericSecretName ||
		name == customdetectors.DBConnectionURIName ||
		name == customdetectors.EntropyName
}

var placeholderMarkers = classify.PlaceholderMarkers()

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

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

func routeLabel(path string) string {
	switch path {
	case "/analyze", "/health", "/readyz", "/metrics":
		return path
	default:
		return "other"
	}
}

func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodHead, http.MethodOptions:
		return method
	default:
		return "other"
	}
}

func accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			panicVal := recover()
			status := rec.status
			if panicVal != nil {
				status = http.StatusInternalServerError
			}
			httpRequestsTotal.WithLabelValues(methodLabel(r.Method), routeLabel(r.URL.Path), strconv.Itoa(status)).Inc()
			log.Printf("request method=%q path=%q status=%d dur=%s remote=%s req=%q",
				r.Method, r.URL.Path, status, time.Since(start), r.RemoteAddr, r.Header.Get("X-Request-Id"))
			if panicVal != nil {
				panic(panicVal)
			}
		}()
		next.ServeHTTP(rec, r)
	})
}
