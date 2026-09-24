package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const shippedTestKey = "test-key-not-a-real-credential"

// startShippedAnalyzer builds the analyzer and runs it exactly as the image
// does -- its own process, its own config read from the environment, reached
// over HTTP. Every other test in this package calls the scanner in process
// with a config built by hand, so nothing else here exercises the artifact
// that actually ships.
func startShippedAnalyzer(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "analyzer")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=1")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the analyzer: %v\n%s", err, out)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PORT=%d", port),
		"TRUFFLEHOG_API_KEY="+shippedTestKey,
	)
	for name, value := range prodEnv { // the deployed configuration
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting the analyzer: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			t.Logf("analyzer output:\n%s", logs.String())
		}
	})

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(base + "/readyz"); err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return base
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("the analyzer never became ready\n%s", logs.String())
	return ""
}

func postAnalyze(t *testing.T, base, key, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, base+"/analyze", strings.NewReader(body))
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("posting to /analyze: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func analyzeDoc(t *testing.T, base, doc string) []analyzeResult {
	t.Helper()
	payload, err := json.Marshal(analyzeRequest{Text: doc, ScoreThreshold: 0.45})
	if err != nil {
		t.Fatalf("encoding the request: %v", err)
	}
	status, body := postAnalyze(t, base, shippedTestKey, string(payload))
	if status != http.StatusOK {
		t.Fatalf("/analyze returned %d: %s", status, body)
	}
	var results []analyzeResult
	if err := json.Unmarshal([]byte(body), &results); err != nil {
		t.Fatalf("decoding %q: %v", body, err)
	}
	return results
}

func reported(results []analyzeResult, doc, value string) bool {
	for _, r := range results {
		if r.Start >= 0 && r.End <= len([]rune(doc)) {
			if string([]rune(doc)[r.Start:r.End]) == value {
				return true
			}
		}
	}
	return false
}

// The whole battery runs against one binary: building and booting it is the
// expensive part, and the cases are independent of each other.
func TestTheShippedBinaryUnderTheDeployedConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the analyzer binary")
	}
	const secret = "aB3xKp9Qm2Lr7TzWqDvNcEd1Ff5Gg6Hh"
	const neighbour = "Qz7Lm4Rt9Wx2Yv6Bn3Kc8Jd5Hf1Gp0S"
	base := startShippedAnalyzer(t)

	// B1 -- the rule itself, through the door the gateway uses
	t.Run("a borrowed keyword does not carry a digest into a finding", func(t *testing.T) {
		doc := `{"api_key": "` + neighbour + `", "sha256": "` + secret + `"}`
		got := analyzeDoc(t, base, doc)
		if reported(got, doc, secret) {
			t.Errorf("the digest was reported by the shipped binary")
		}
		if !reported(got, doc, neighbour) {
			t.Errorf("the api_key beside it was not reported")
		}
	})

	// B2 -- recall, through the same door
	t.Run("a credential is still reported", func(t *testing.T) {
		for _, doc := range []string{
			`{"api_key": "` + neighbour + `", "sha256_key": "` + secret + `"}`,
			`{"api_key": "` + neighbour + `", "signing sha256": "` + secret + `"}`,
			`password = "sha256=` + secret + `"`,
			"password = {\n  \"sha256\": \"" + secret + "\"\n}",
			"auth: md5=" + secret,
		} {
			if !reported(analyzeDoc(t, base, doc), doc, secret) {
				t.Errorf("the shipped binary did not report the secret in %q", doc)
			}
		}
	})

	// B3 -- a suppressed value must not come back in the response
	t.Run("a suppressed value is not echoed", func(t *testing.T) {
		doc := `{"api_key": "` + neighbour + `", "sha256": "` + secret + `"}`
		payload, _ := json.Marshal(analyzeRequest{Text: doc, ScoreThreshold: 0.45})
		_, body := postAnalyze(t, base, shippedTestKey, string(payload))
		if strings.Contains(body, secret) {
			t.Errorf("the response body carried the suppressed value")
		}
	})

	// B4 -- the guards on the handler still hold
	t.Run("the handler rejects what it should", func(t *testing.T) {
		payload, _ := json.Marshal(analyzeRequest{Text: "sha256=" + secret, ScoreThreshold: 0.45})
		if status, _ := postAnalyze(t, base, "", string(payload)); status != http.StatusUnauthorized {
			t.Errorf("no bearer token returned %d, want 401", status)
		}
		if status, _ := postAnalyze(t, base, "wrong-key", string(payload)); status != http.StatusUnauthorized {
			t.Errorf("a wrong bearer token returned %d, want 401", status)
		}
		// Malformed input must not crash the scanner or produce findings. The
		// status it comes back with is a separate, older defect: the handler
		// sets 400 for its own metric but writeJSON never sends a header, so
		// the caller is told 200 while Prometheus records 400. That predates
		// this change and belongs with the handler, so it is reported rather
		// than asserted either way here.
		status, body := postAnalyze(t, base, shippedTestKey, "{not json")
		if status >= 500 {
			t.Errorf("malformed JSON returned %d", status)
		}
		if strings.TrimSpace(body) != "[]" {
			t.Errorf("malformed JSON produced %q, want no findings", strings.TrimSpace(body))
		}
	})

	// C1/C2 -- suppression reasons about the whole request, and the request can
	// be larger than one scan window
	t.Run("a document past the scan window", func(t *testing.T) {
		filler := strings.Repeat("lorem ipsum dolor sit amet consectetur\n", 220) // ~8KB
		if len(filler) <= scanWindowSize+scanWindowPeek {
			t.Fatalf("filler is %d bytes, not past the %d-byte window", len(filler), scanWindowSize+scanWindowPeek)
		}
		doc := `{"api_key": "` + neighbour + `",` + "\n" + filler + `"sha256": "` + secret + `"}`
		got := analyzeDoc(t, base, doc)
		if reported(got, doc, secret) {
			t.Errorf("the digest was reported in a document past the window")
		}
		tail := filler + `api_key=` + neighbour
		if !reported(analyzeDoc(t, base, tail), tail, neighbour) {
			t.Errorf("a credential at the far end of a large document was not reported")
		}
	})

	// D1 -- a multibyte name is still one name
	t.Run("a multibyte label", func(t *testing.T) {
		for _, doc := range []string{
			`{"api_key": "` + neighbour + `", "clé_sha256": "` + secret + `"}`,
			`{"api_key": "` + neighbour + `", "ключ": "` + secret + `"}`,
		} {
			if !reported(analyzeDoc(t, base, doc), doc, secret) {
				t.Errorf("a multibyte label did not keep its value reportable: %q", doc)
			}
		}
		doc := `{"api_key": "` + neighbour + `", "sha256": "` + secret + `", "é": "x"}`
		if reported(analyzeDoc(t, base, doc), doc, secret) {
			t.Errorf("a multibyte field elsewhere changed the digest's own label")
		}
	})
}
