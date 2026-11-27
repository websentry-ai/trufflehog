package main

import (
	"go/parser"
	"go/token"
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
