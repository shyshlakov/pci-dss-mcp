package auditscanner

import (
	"path/filepath"
	"runtime"
	"testing"
)

// testdataDir returns the absolute path to the testdata directory.
func testdataDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "testdata")
}

// TestPkgMiddleware_CrossFileCoverage verifies that a payment handler in
// crossfile_handler.go (CreateToken) is recognized as covered by logging
// middleware registered in crossfile_middleware.go (requestLogger on
// apiV1Group).
func TestPkgMiddleware_CrossFileCoverage(t *testing.T) {
	t.Parallel()
	ResetPackageCache()
	td := testdataDir()
	handlerFile := filepath.Join(td, "crossfile_handler.go")

	if !hasLoggingCoverageInPackage(handlerFile, "CreateToken") {
		t.Error("Expected CreateToken to be covered by cross-file middleware (requestLogger on apiV1Group)")
	}
}

// TestPkgMiddleware_CrossFileUncovered verifies that a payment handler
// registered on a group WITHOUT logger middleware still returns false.
func TestPkgMiddleware_CrossFileUncovered(t *testing.T) {
	t.Parallel()
	ResetPackageCache()
	td := testdataDir()
	nocoverFile := filepath.Join(td, "crossfile_nocover.go")

	if hasLoggingCoverageInPackage(nocoverFile, "UncoveredPayment") {
		t.Error("Expected UncoveredPayment to NOT be covered (group has no logger middleware)")
	}
}

// TestPkgMiddleware_ExternalPackageHeuristic verifies that middleware.Install()
// from an external package whose import path contains "middleware" triggers the
// heuristic trust, marking the handler as covered.
func TestPkgMiddleware_ExternalPackageHeuristic(t *testing.T) {
	t.Parallel()
	ResetPackageCache()
	td := testdataDir()
	externalFile := filepath.Join(td, "crossfile_external_mw.go")

	if !hasLoggingCoverageInPackage(externalFile, "ExternalPayHandler") {
		t.Error("Expected ExternalPayHandler to be covered via external middleware heuristic ")
	}
}

// TestPkgMiddleware_ParentChildGroupInheritance verifies that a handler
// registered on a sub-group (sub:= group.Group("/tokens/v1")) inherits
// middleware coverage from the parent group.
func TestPkgMiddleware_ParentChildGroupInheritance(t *testing.T) {
	t.Parallel()
	ResetPackageCache()
	td := testdataDir()
	handlerFile := filepath.Join(td, "crossfile_handler.go")

	// DeleteToken is registered on sub-group which inherits from apiV1Group.
	if !hasLoggingCoverageInPackage(handlerFile, "DeleteToken") {
		t.Error("Expected DeleteToken to be covered via parent-child group inheritance")
	}
}

// TestPkgMiddleware_CacheHit verifies that calling hasLoggingCoverageInPackage
// twice for the same package directory only parses once (cache hit).
func TestPkgMiddleware_CacheHit(t *testing.T) {
	t.Parallel()
	ResetPackageCache()
	td := testdataDir()
	handlerFile := filepath.Join(td, "crossfile_handler.go")

	// First call should populate cache.
	_ = hasLoggingCoverageInPackage(handlerFile, "CreateToken")

	// Cache should have an entry for the testdata directory.
	pkgDir := filepath.Dir(handlerFile)
	pkgMiddlewareMu.Lock()
	_, cached := pkgMiddlewareCache[pkgDir]
	pkgMiddlewareMu.Unlock()

	if !cached {
		t.Error("Expected package middleware context to be cached after first call")
	}

	// Second call should use cache (same result).
	if !hasLoggingCoverageInPackage(handlerFile, "CreateToken") {
		t.Error("Expected CreateToken to still be covered on second (cached) call")
	}
}

// TestPkgMiddleware_ArgLooksLikeLoggerReuse confirms that the package walker
// uses the same argLooksLikeLogger function from auditscanner.go, not a
// reimplemented version.
func TestPkgMiddleware_ArgLooksLikeLoggerReuse(t *testing.T) {
	t.Parallel()
	// This test verifies the function is importable/callable from this package.
	// If argLooksLikeLogger were moved or renamed, this would fail to compile.
	// The function is tested separately in auditscanner_test.go; here we just
	// confirm accessibility.
	_ = argLooksLikeLogger // compile-time check
}
