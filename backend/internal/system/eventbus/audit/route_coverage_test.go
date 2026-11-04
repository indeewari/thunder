// Copyright 2026 The ThunderID Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/thunder-id/thunderid/internal/system/utils"
)

// minRegisteredRoutes is fewer mutating routes than the backend registers with a literal pattern, so
// a scan that stops finding them fails rather than passing on nothing.
const minRegisteredRoutes = 80

// sampleWildcardPattern finds the wildcards of a route pattern, which a sample path fills in.
var sampleWildcardPattern = regexp.MustCompile(`\{[^}]+\}`)

// registrationFuncs are the calls whose first argument is a route pattern.
var registrationFuncs = map[string]bool{"HandleFunc": true, "Handle": true, "WithCORS": true}

// RouteCoverageTestSuite checks every mutating route the backend registers against the route table.
// The server mux cannot be built in a unit test, so the routes are read from the source: only a
// pattern written as one string literal is seen, and one assembled from constants is not.
type RouteCoverageTestSuite struct {
	suite.Suite
}

func TestRouteCoverageTestSuite(t *testing.T) {
	suite.Run(t, new(RouteCoverageTestSuite))
}

// A newly registered mutating route is either named by the table or explicitly excluded, so its
// calls are not recorded under the generic name by accident.
func (s *RouteCoverageTestSuite) TestEveryRegisteredMutatingRouteIsNamedOrExcluded() {
	patterns := s.registeredMutatingPatterns()
	s.GreaterOrEqual(len(patterns), minRegisteredRoutes)

	for _, pattern := range patterns {
		method, path, _ := strings.Cut(pattern, " ")
		sample := samplePath(path)
		_, _, matched := matchManagementRoute(method, sample)
		s.True(matched || isExcluded(sample), "%s is neither in the route table nor excluded", pattern)
	}
}

// registeredMutatingPatterns returns the literal mutating route patterns registered under internal.
func (s *RouteCoverageTestSuite) registeredMutatingPatterns() []string {
	_, file, _, ok := runtime.Caller(0)
	s.Require().True(ok)
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")

	var patterns []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			if pattern, ok := registeredPattern(node); ok {
				patterns = append(patterns, pattern)
			}
			return true
		})
		return nil
	})
	s.Require().NoError(err)
	return patterns
}

// registeredPattern returns the mutating route pattern a registration call passes as a literal.
func registeredPattern(node ast.Node) (string, bool) {
	call, ok := node.(*ast.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !registrationFuncs[selector.Sel.Name] {
		return "", false
	}
	literal, ok := call.Args[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	pattern, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	method, path, found := strings.Cut(pattern, " ")
	if !found || !utils.IsMutatingMethod(method) || !strings.HasPrefix(path, "/") {
		return "", false
	}
	return pattern, true
}

// samplePath fills the wildcards of a route path, and the remainder of a catch-all route, with a
// value a request could carry.
func samplePath(path string) string {
	sample := sampleWildcardPattern.ReplaceAllString(path, "x")
	if strings.HasSuffix(sample, "/") {
		sample += "x"
	}
	return sample
}
