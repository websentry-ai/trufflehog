package main

import (
	"context"
	"strings"
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
