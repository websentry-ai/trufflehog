package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/joho/godotenv"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/classify"
	"github.com/trufflesecurity/trufflehog/v3/cmd/analyzer/customdetectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
	regexp "github.com/wasilibs/go-re2"
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

		// A request that cannot be scanned says so in its status: an empty list on
		// 200 would read as "no secrets" to a caller that never scanned anything.
		var req analyzeRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err == nil {
			// The decoder stops at the first value, so bytes past it, and past the
			// limit, go unread unless drained here.
			_, err = io.Copy(io.Discard, r.Body)
		}
		if err != nil || req.Text == "" {
			status = http.StatusBadRequest
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				status = http.StatusRequestEntityTooLarge
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode([]analyzeResult{})
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

// Several detectors pair two matches -- a token and a vendor URL, or two halves
// of a credential -- anywhere in the data they are handed, so a whole request
// lets unrelated halves combine. The window bounds how far apart they may be,
// and is sized to how a credential is written down: a token and the host it
// belongs with sit in the same block, a few hundred bytes apart.
const (
	scanWindowSize = 2 * 1024
	scanWindowPeek = 1024
)

func (s *scanner) scan(ctx context.Context, data []byte, threshold float64) []analyzeResult {
	start := time.Now()
	defer func() { scanDuration.Observe(time.Since(start).Seconds()) }()

	kept := s.scanText(ctx, data, threshold)
	if decoded := s.scanEncoded(ctx, data, threshold, kept); len(decoded) > 0 {
		// A named credential found inside an encoded run replaces the generic
		// finding that only saw the run as random-looking text.
		var named []analyzeResult
		for _, d := range decoded {
			if !isGenericDetectorName(d.EntityType) {
				named = append(named, d)
			}
		}
		out := kept[:0:0]
		for _, k := range kept {
			if !isGenericDetectorName(k.EntityType) || !insideAny(named, k.Start, k.End) {
				out = append(out, k)
			}
		}
		kept = dedupeIdentical(append(out, decoded...))
		sort.SliceStable(kept, func(i, j int) bool { return kept[i].Start < kept[j].Start })
	}
	return s.record(ctx, kept)
}

// scanText runs every detector over data and resolves the results, without
// looking inside encoded runs.
func (s *scanner) scanText(ctx context.Context, data []byte, threshold float64) []analyzeResult {
	// Computed once over the whole request so windowing cannot weaken it.
	var shapes map[string]int
	if s.mode != suppressionOff {
		shapes = documentShapes(data)
	}

	var all []analyzeResult
	if len(data) <= scanWindowSize+scanWindowPeek {
		all = s.detect(ctx, s.core, data, threshold, 0)
	} else {
		for off := 0; off < len(data); {
			end := runeBoundary(data, off+scanWindowSize+scanWindowPeek)
			// Offsets are reported in runes, so the window's own start has to be
			// counted the same way before it can be added back.
			all = append(all, s.detect(ctx, s.core, data[off:end], threshold, utf8.RuneCount(data[:off]))...)
			if end == len(data) {
				break
			}
			off = runeBoundary(data, off+scanWindowSize)
		}
		if s.longFormCore != nil {
			all = append(all, s.detect(ctx, s.longFormCore, data, threshold, 0)...)
		}
	}

	// Overlap resolution and suppression both reason about the request as a
	// whole, so they run once on the merged set rather than inside a window. URL
	// logins are placed after suppression, so a vendor match dropped as noise
	// cannot take a login down with it.
	var logins, others []analyzeResult
	for _, r := range dedupeIdentical(all) {
		if r.EntityType == customdetectors.URLLoginCredentialName {
			logins = append(logins, r)
		} else {
			others = append(others, r)
		}
	}
	kept := s.applySuppression(ctx, dedupeOverlapping(others), data, shapes)
	if len(logins) > 0 {
		kept = placeLogins(kept, s.applySuppression(ctx, logins, data, shapes))
	}
	return kept
}

// base64Run is a run long enough to hide a credential once decoded.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{24,}={0,2}`)

const (
	maxEncodedRun = 64 * 1024
	// The pass stops once this much text has been decoded, which bounds its cost
	// by size rather than by how many short runs a prompt happens to contain.
	maxDecodedBytes = 256 * 1024
)

// scanEncoded decodes base64 runs that hold readable text and scans that text,
// reporting each credential found over the encoded run it came from. Runs a
// named finding already covers are skipped, and so is anything that decodes to
// binary, such as an image.
func (s *scanner) scanEncoded(ctx context.Context, data []byte, threshold float64, kept []analyzeResult) []analyzeResult {
	var out []analyzeResult
	decodedBytes := 0
	// Matches come in order, so rune offsets are counted forward from the last
	// one rather than from the start of the request each time, and named findings
	// are swept in start order alongside them.
	byteAt, runeAt := 0, 0
	named := namedByStart(kept)
	next, reach := 0, -1
	for _, part := range encodedParts(ctx, data, base64Run.FindAllIndex(data, -1)) {
		runeAt += utf8.RuneCount(data[byteAt:part.from])
		byteAt = part.from
		start := runeAt
		end := start + utf8.RuneCount(data[part.from:part.to])
		// A run is covered when some named finding starting at or before it
		// reaches its end, which the furthest such end decides.
		for ; next < len(named) && named[next].Start <= start; next++ {
			reach = max(reach, named[next].End)
		}
		if reach >= end {
			continue
		}
		decoded := part.decoded
		if decodedBytes += len(decoded); decodedBytes > maxDecodedBytes {
			break
		}
		found := s.scanText(ctx, decoded, threshold)
		hasNamed := false
		for _, f := range found {
			hasNamed = hasNamed || !isGenericDetectorName(f.EntityType)
		}
		// A generic result adds nothing where the plain scan already flagged the run.
		if !hasNamed && overlapsAny(kept, start, end) {
			continue
		}
		seen := map[string]bool{}
		for _, f := range found {
			if seen[f.EntityType] || (hasNamed && isGenericDetectorName(f.EntityType)) {
				continue
			}
			seen[f.EntityType] = true
			f.Start, f.End = start, end
			out = append(out, f)
		}
	}
	return out
}

// encodedPart is a stretch of the request that decodes to readable text.
type encodedPart struct {
	from, to int
	decoded  []byte
}

// encodedParts decodes each base64 run, in order. A value wrapped across lines
// is decoded whole; when the whole does not decode, the lines that do not
// decode on their own split it into stretches that are each decoded whole.
func encodedParts(ctx context.Context, data []byte, locs [][]int) []encodedPart {
	decode := func(from, to int) (encodedPart, bool) {
		if to-from > maxEncodedRun {
			return encodedPart{}, false
		}
		decoded, ok := decodeBase64Text(data[from:to])
		return encodedPart{from, to, decoded}, ok
	}
	var out []encodedPart
	for _, lines := range wrappedRuns(data, locs) {
		if ctx.Err() != nil {
			break
		}
		if p, ok := decode(lines[0][0], lines[len(lines)-1][1]); ok {
			out = append(out, p)
			continue
		}
		// Full-width lines are whole base64 quanta, so a line that does not decode
		// to text on its own (binary, or unrelated text) is not part of a readable
		// value. It splits the run, and each stretch around it is one value.
		for i := 0; i < len(lines); {
			j := i
			for j < len(lines) {
				if !decodesOnItsOwn(data[lines[j][0]:lines[j][1]]) {
					break
				}
				j++
			}
			if j == i {
				i++
				continue
			}
			if p, ok := decode(lines[i][0], lines[j-1][1]); ok {
				out = append(out, p)
			} else {
				for _, l := range lines[i:j] {
					if p, ok := decode(l[0], l[1]); ok {
						out = append(out, p)
					}
				}
			}
			i = j
		}
	}
	return out
}

// wrappedRuns groups runs that are one base64 value wrapped across lines:
// base64 tools and MIME wrap at 64 or 76 characters from the start of a line,
// so a full-width line continues with the base64 that starts the next line,
// however short. Padding ends a value, and a run that begins mid-line, after a
// label, stands alone.
func wrappedRuns(data []byte, locs [][]int) [][][2]int {
	var out [][][2]int
	for i := 0; i < len(locs); i++ {
		lines := [][2]int{{locs[i][0], locs[i][1]}}
		atLineStart := locs[i][0] == 0 || data[locs[i][0]-1] == '\n'
		for atLineStart {
			cur := lines[len(lines)-1]
			if w := cur[1] - cur[0]; (w != 64 && w != 76) || data[cur[1]-1] == '=' {
				break
			}
			next := cur[1]
			if bytes.HasPrefix(data[next:], []byte("\r\n")) {
				next += 2
			} else if bytes.HasPrefix(data[next:], []byte("\n")) {
				next++
			} else {
				break
			}
			k := next
			for k < len(data) && (isBase64Byte(data[k]) || data[k] == '-' || data[k] == '_') {
				k++
			}
			if k == next {
				break
			}
			lines = append(lines, [2]int{next, k})
		}
		end := lines[len(lines)-1][1]
		for i+1 < len(locs) && locs[i+1][0] < end {
			i++
		}
		out = append(out, lines)
	}
	return out
}

func decodeBase64Text(run []byte) ([]byte, bool) {
	run = bytes.ReplaceAll(bytes.ReplaceAll(run, []byte("\r"), nil), []byte("\n"), nil)
	trimmed := bytes.TrimRight(run, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(string(trimmed))
		if err == nil && isReadableText(decoded) {
			return decoded, true
		}
	}
	return nil, false
}

// decodesOnItsOwn reports whether one wrapped line decodes to readable text. A
// multi-byte character can straddle two lines, so a partial one at either edge
// is ignored, and a line holding only part of one counts.
func decodesOnItsOwn(line []byte) bool {
	trimmed := string(bytes.TrimRight(line, "="))
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(trimmed)
		if err != nil {
			continue
		}
		for n := 0; n < utf8.UTFMax-1 && len(b) > 0 && !utf8.RuneStart(b[0]); n++ {
			b = b[1:]
		}
		for k := 1; k < utf8.UTFMax && k <= len(b); k++ {
			if utf8.RuneStart(b[len(b)-k]) {
				if !utf8.FullRune(b[len(b)-k:]) {
					b = b[:len(b)-k]
				}
				break
			}
		}
		if len(b) == 0 || isReadableText(b) {
			return true
		}
	}
	return false
}

// isReadableText reports whether b is UTF-8 made almost entirely of printable
// characters, the shape of a config or command rather than binary data.
func isReadableText(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	printable := 0
	total := 0
	for _, r := range string(b) {
		total++
		if unicode.IsPrint(r) || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return printable*100 >= total*95
}

// namedByStart returns the named detectors' findings ordered by start. A
// generic finding is left out: decoding its run may name it.
func namedByStart(findings []analyzeResult) []analyzeResult {
	var named []analyzeResult
	for _, f := range findings {
		if !isGenericDetectorName(f.EntityType) {
			named = append(named, f)
		}
	}
	sort.Slice(named, func(i, j int) bool { return named[i].Start < named[j].Start })
	return named
}

func overlapsAny(findings []analyzeResult, start, end int) bool {
	for _, f := range findings {
		if f.Start < end && f.End > start {
			return true
		}
	}
	return false
}

// insideAny reports whether [start, end) lies within one of the findings.
func insideAny(findings []analyzeResult, start, end int) bool {
	for _, f := range findings {
		if f.Start <= start && f.End >= end {
			return true
		}
	}
	return false
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

// dedupeIdentical drops the repeats the peek overlap produces. The entity is
// part of the key: two detectors reporting the same span are not duplicates,
// and choosing between them is dedupeOverlapping's job.
func dedupeIdentical(in []analyzeResult) []analyzeResult {
	type key struct {
		entity     string
		start, end int
	}
	seen := make(map[key]struct{}, len(in))
	out := make([]analyzeResult, 0, len(in))
	for _, r := range in {
		k := key{r.EntityType, r.Start, r.End}
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

// detect runs one core over one slice. The core is an argument because the
// scanner is shared across concurrent requests and must never be mutated.
func (s *scanner) detect(ctx context.Context, core *ahocorasick.Core, data []byte, threshold float64, runeBase int) []analyzeResult {
	reqID := reqIDFrom(ctx)
	out := []analyzeResult{}
	runes := &runeIndex{data: data}
	for _, match := range core.FindDetectorMatches(data) {
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
			// A login's password meets its own placeholder rule in suppression.
			if entity != customdetectors.URLLoginCredentialName && isObviousPlaceholder(placeholderSubject(entity, res.Raw)) {
				placeholdersSuppressedTotal.WithLabelValues(entity).Inc()
				continue
			}
			at := -1
			if res.HasChunkOffset() {
				at = int(res.ChunkOffset())
			}
			start, end, ok := runes.offsets(res.Raw, at)
			if !ok && entity == "Docker" {
				// Docker builds its value as base64 of user:password when a config
				// lists them in plain text; the password field is what the prompt holds.
				if pw := classify.BasicAuthPassword(string(res.Raw)); pw != "" {
					if i := passwordFieldAt(data, pw); i >= 0 {
						start, end, ok = runes.offsets([]byte(pw), i)
					}
				}
			}
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
	return out
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

// placeLogins adds each login unless a vendor finding covers its whole password,
// in which case the vendor keeps its name. Otherwise the login replaces what it
// overlaps, since a narrower finding would leave part of the password unredacted.
// kept is sorted and non-overlapping, so what a login overlaps is one run of it.
func placeLogins(kept, logins []analyzeResult) []analyzeResult {
	dropped := make([]bool, len(kept))
	out := make([]analyzeResult, 0, len(kept)+len(logins))
	for _, l := range logins {
		lo := sort.Search(len(kept), func(i int) bool { return kept[i].End > l.Start })
		hi, covered := lo, false
		for ; hi < len(kept) && kept[hi].Start < l.End; hi++ {
			k := kept[hi]
			if !dropped[hi] && entityRank(k.EntityType) < entityRank(l.EntityType) && k.Start <= l.Start && k.End >= l.End {
				covered = true
			}
		}
		if covered {
			continue
		}
		for i := lo; i < hi; i++ {
			dropped[i] = true
		}
		out = append(out, l)
	}
	for i, k := range kept {
		if !dropped[i] {
			out = append(out, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Start < out[j].Start })
	return out
}

func entityRank(name string) int {
	switch name {
	case customdetectors.EntropyName:
		return 2
	case customdetectors.GenericSecretName, customdetectors.URLLoginCredentialName:
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

// placeholderSubject is the part of a finding the placeholder check reads. An
// email/token login is reported whole, but only its token says whether it is real:
// "jane.sample@acme.com" is an ordinary address.
func placeholderSubject(entity string, raw []byte) string {
	if entity == customdetectors.EmailTokenLoginName {
		if _, tok, ok := bytes.Cut(raw, []byte("/token:")); ok {
			return string(tok)
		}
	}
	return string(raw)
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

// offsets locates raw in data: at byte at when the detector reported where its
// match was, otherwise at raw's first occurrence.
func offsets(data, raw []byte, at int) (int, int, bool) {
	return (&runeIndex{data: data}).offsets(raw, at)
}

// runeIndex turns byte offsets into rune offsets, counting on from the previous
// lookup, so one detector's ascending results cost one pass over the data.
type runeIndex struct {
	data       []byte
	byte, rune int
}

func (x *runeIndex) offsets(raw []byte, at int) (int, int, bool) {
	if len(raw) == 0 {
		return 0, 0, false
	}
	i := at
	if i < 0 || i+len(raw) > len(x.data) || !bytes.Equal(x.data[i:i+len(raw)], raw) {
		i = bytes.Index(x.data, raw)
	}
	if i < 0 {
		return 0, 0, false
	}
	if i < x.byte {
		x.byte, x.rune = 0, 0
	}
	x.rune += utf8.RuneCount(x.data[x.byte:i])
	x.byte = i
	return x.rune, x.rune + utf8.RuneCount(raw), true
}

// passwordFieldKey matches a JSON "password" key up to its value's opening
// quote, escaped or not.
var passwordFieldKey = regexp.MustCompile(`(?i)\\*"password\\*"\s*:\s*\\*"`)

// passwordFieldAt returns the byte offset of pw as the value of a "password"
// field, or -1.
func passwordFieldAt(data []byte, pw string) int {
	for _, loc := range passwordFieldKey.FindAllIndex(data, -1) {
		rest := data[loc[1]:]
		if bytes.HasPrefix(rest, []byte(pw)) {
			if after := rest[len(pw):]; bytes.HasPrefix(after, []byte(`"`)) || bytes.HasPrefix(after, []byte(`\"`)) {
				return loc[1]
			}
		}
	}
	return -1
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
