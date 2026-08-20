package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// A multibyte rune straddling a window boundary must not shift the offsets a
// finding is reported at.
func TestWindowBoundaryRespectsRunes(t *testing.T) {
	pad := strings.Repeat("日", 4000)
	key := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	text := pad + "\nGITHUB_TOKEN=" + key + "\n" + pad
	if utf8.RuneStart(text[scanWindowSize]) {
		t.Skip("boundary happens to land on a rune start")
	}
	runes := []rune(text)
	for _, r := range newBuiltScanner(t).scan(context.Background(), []byte(text), 0.75) {
		if r.Start < 0 || r.End > len(runes) {
			t.Fatalf("offset out of range: %d-%d of %d runes", r.Start, r.End, len(runes))
		}
		if got := string(runes[r.Start:r.End]); got != key {
			t.Errorf("offset drift: reported %q, want %q", got, key)
		}
	}
}

// A PEM block has no length bound and runs past the peek, so windowing alone
// would split it.
func TestLongPrivateKeySurvivesWindowing(t *testing.T) {
	body := strings.Repeat("MIIEowIBAAKCAQEAx7Vn8Q2mKpLd9RtYuIoP3aSdFgHjKlZxCvBnMqWeRtYuIoPa\n", 200)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----"
	if len(pem) <= scanWindowPeek {
		t.Fatalf("fixture is %d bytes, not longer than the peek", len(pem))
	}
	filler := strings.Repeat("routine log line about a deployment step. ", 200)
	text := filler + "\n" + pem + "\n" + filler

	for _, r := range newBuiltScanner(t).scan(context.Background(), []byte(text), 0.75) {
		if strings.Contains(r.EntityType, "rivate") {
			return
		}
	}
	t.Fatalf("private key of %d bytes was not detected across windows", len(pem))
}

// A finding past the first window must still be reported against the whole
// request, not against the window it happened to land in.
func TestWindowingKeepsOffsetsAbsolute(t *testing.T) {
	filler := strings.Repeat("routine log line describing a deployment step. ", 700)
	key := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	text := filler + "\nGITHUB_TOKEN=" + key + "\n" + filler
	runes := []rune(text)
	for _, r := range newBuiltScanner(t).scan(context.Background(), []byte(text), 0.75) {
		if string(runes[r.Start:r.End]) == key {
			return
		}
	}
	t.Fatal("token past the first window was not reported at its true offset")
}

// Bulk-list suppression asks whether a value is one of many alike in the
// document, so it has to be judged over the whole request rather than a window.
func TestBulkSuppressionSeesWholeRequest(t *testing.T) {
	var spread strings.Builder
	for i := 0; i < 30; i++ {
		spread.WriteString("token ghp_")
		for j := 0; j < 36; j++ {
			spread.WriteByte("aB3xK9mQ7pL2vN8wRt5Yc1dE4fG6hJ0kS"[(i*7+j*3)%33])
		}
		spread.WriteString("\n")
		spread.WriteString(strings.Repeat("routine log line about a deployment step. ", 60))
	}
	whole := documentShapes([]byte(spread.String()))
	window := documentShapes([]byte(spread.String()[:scanWindowSize]))
	for k, n := range whole {
		if n >= bulkListMinCount && window[k] >= n {
			t.Errorf("shape %q counts %d in a window vs %d whole -- the window view is not narrower", k, window[k], n)
		}
	}
}

// The scanner is shared across concurrent requests, so nothing in the scan path
// may mutate it. Run under -race this fails if a core is swapped in place.
func TestConcurrentScansDoNotShareState(t *testing.T) {
	s := newBuiltScanner(t)
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" +
		strings.Repeat("MIIEowIBAAKCAQEAx7Vn8Q2mKpLd9RtYuIoP3aSdFgHjKlZxCvBnMqWeRtYuIoPa\n", 200) +
		"-----END RSA PRIVATE KEY-----"
	filler := strings.Repeat("routine log line about a deployment step. ", 300)
	long := []byte(filler + "\n" + pem + "\n" + filler)
	short := []byte("export GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz")

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := short
			if i%2 == 0 {
				data = long
			}
			if got := len(s.scan(context.Background(), data, 0.75)); got == 0 {
				t.Errorf("goroutine %d found nothing", i)
			}
		}(i)
	}
	wg.Wait()
}

// Any detector whose match can exceed the peek must be scanned over the whole
// request, or a window boundary cuts its secret in half.
func TestLongMatchDetectorsBypassWindowing(t *testing.T) {
	cfg, err := scannerConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	dets, err := buildDetectors(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var oversized []string
	for _, d := range dets {
		if sz, ok := d.(interface{ MaxSecretSize() int64 }); ok && sz.MaxSecretSize() > scanWindowPeek {
			oversized = append(oversized, fmt.Sprintf("%T", d))
		}
	}
	if len(oversized) == 0 {
		t.Fatal("expected some detectors to declare a match longer than the peek")
	}

	s, err := buildScanner(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.longFormCore == nil {
		t.Fatalf("%d detectors declare a match longer than the peek but none is routed whole: %v",
			len(oversized), oversized)
	}
}

// A paired detector must never reach the long-form core, and a long unpaired one
// must.
func TestLongFormSelection(t *testing.T) {
	cfg, err := scannerConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	dets, err := buildDetectors(cfg)
	if err != nil {
		t.Fatal(err)
	}
	picked := map[string]bool{}
	for _, d := range longFormDetectors(dets) {
		picked[fmt.Sprintf("%T", d)] = true
	}
	for name := range pairedLongForm {
		if picked[name] {
			t.Errorf("%s is paired and must stay windowed", name)
		}
	}
	if !picked["*jwt.Scanner"] {
		t.Error("jwt matches up to 4KB and must see the whole request")
	}
	if !picked["*custom_detectors.CustomRegexWebhook"] {
		t.Error("the PEM block has no length bound and must see the whole request")
	}
}
