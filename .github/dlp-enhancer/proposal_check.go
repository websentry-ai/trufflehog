// Parse the proposed test without executing it or loading the detector package.
package main

import (
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"strconv"
)

func main() {
	file, err := parser.ParseFile(token.NewFileSet(), "proposal_test.go", os.Stdin, parser.ParseComments)
	if err != nil || len(os.Args) != 2 || !validDeclarations(file, os.Args[1]) {
		fmt.Fprintln(os.Stderr, "Invalid Go test file")
		os.Exit(1)
	}
}

func validDeclarations(file *ast.File, key string) bool {
	if file.Name.Name != "main" {
		return false
	}
	for _, imp := range file.Imports {
		name, err := strconv.Unquote(imp.Path.Value)
		if err != nil || name == "C" {
			return false
		}
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if constraint.IsGoBuild(comment.Text) || constraint.IsPlusBuild(comment.Text) {
				return false
			}
		}
	}
	tests := 0
	for _, decl := range file.Decls {
		if imp, ok := decl.(*ast.GenDecl); ok && imp.Tok == token.IMPORT {
			continue
		}
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Name.Name != "TestDLPEnhancer_"+key {
			return false
		}
		tests++
	}
	return tests == 1
}
