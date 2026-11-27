package main

import (
	"go/parser"
	"go/token"
	"os/exec"
	"strings"
	"testing"
)

func TestCaseScopedDeclaration(t *testing.T) {
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{"import \"testing\"\nfunc TestDLPEnhancer_abc(t *testing.T) {}", true},
		{"func TestDLPEnhancer_xyz() {}", false},
		{"var shared = 1\nfunc TestDLPEnhancer_abc() {}", false},
		{"func TestDLPEnhancer_abc() {}\nfunc helper() {}", false},
		{"import \"testing\"", false},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", "package main\n"+tc.source, 0)
		if err != nil {
			t.Fatal(err)
		}
		if validDeclarations(file, "abc") != tc.want {
			t.Errorf("unexpected verdict for %q", tc.source)
		}
	}
}

func TestGeneratorCheckerCommand(t *testing.T) {
	const proposal = "package main\nimport \"testing\"\nfunc TestDLPEnhancer_abc(t *testing.T) {}"
	for _, tc := range []struct {
		header string
		want   bool
	}{
		{"", true},
		{"//go:build ignore\n\n", false},
		{"// +build ignore\n\n", false},
	} {
		cmd := exec.Command("go", "run", "proposal_check.go", "abc")
		cmd.Stdin = strings.NewReader(tc.header + proposal)
		output, err := cmd.CombinedOutput()
		if (err == nil) != tc.want {
			t.Fatalf("header %q: %v, %s", tc.header, err, output)
		}
	}
}
