package sbomscanner

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/licensecheck"
)

const licenseCoverageThreshold = 75.0

var licenseFilenames = []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md"}

var (
	licenseScanner     *licensecheck.Scanner
	licenseScannerOnce sync.Once
	licenseScannerErr  error
)

type LicenseDetection struct {
	SPDXID     string
	Confidence float64
	SourcePath string
}

func getLicenseScanner() (*licensecheck.Scanner, error) {
	licenseScannerOnce.Do(func() {
		licenseScanner, licenseScannerErr = licensecheck.NewScanner(licensecheck.BuiltinLicenses())
		if licenseScannerErr != nil {
			slog.Warn("licensecheck scanner init failed; license detection disabled", "err", licenseScannerErr)
		}
	})
	return licenseScanner, licenseScannerErr
}

func detectLicense(modulePath, version string) LicenseDetection {
	return detectLicenseIn(resolveGomodcache(), modulePath, version)
}

func detectLicenseIn(gomodcache, modulePath, version string) LicenseDetection {
	path, ok := findLicenseFileIn(gomodcache, modulePath, version)
	if !ok {
		return LicenseDetection{}
	}
	return detectLicenseFromFile(path)
}

func detectLicenseFromPath(dir string) LicenseDetection {
	for _, name := range licenseFilenames {
		full := filepath.Join(dir, name)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			return detectLicenseFromFile(full)
		}
	}
	return LicenseDetection{}
}

func detectLicenseFromFile(path string) LicenseDetection {
	body, err := os.ReadFile(path)
	if err != nil {
		return LicenseDetection{}
	}
	sc, err := getLicenseScanner()
	if err != nil || sc == nil {
		return LicenseDetection{SourcePath: path}
	}
	cov := safeLicenseScan(sc, body)
	if cov.Percent < licenseCoverageThreshold || len(cov.Match) == 0 {
		return LicenseDetection{SourcePath: path, Confidence: cov.Percent}
	}
	pick := pickBestMatch(cov.Match)
	return LicenseDetection{SPDXID: pick.ID, Confidence: cov.Percent, SourcePath: path}
}

func safeLicenseScan(sc *licensecheck.Scanner, body []byte) (out licensecheck.Coverage) {
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("licensecheck panic recovered; reporting empty coverage", "panic", r)
			out = licensecheck.Coverage{}
		}
	}()
	return sc.Scan(body)
}

func pickBestMatch(matches []licensecheck.Match) licensecheck.Match {
	best := matches[0]
	bestSpan := best.End - best.Start
	for _, m := range matches[1:] {
		span := m.End - m.Start
		if span > bestSpan || (span == bestSpan && m.ID < best.ID) {
			best, bestSpan = m, span
		}
	}
	return best
}

func findLicenseFile(modulePath, version string) (string, bool) {
	return findLicenseFileIn(resolveGomodcache(), modulePath, version)
}

func findLicenseFileIn(gomodcache, modulePath, version string) (string, bool) {
	if gomodcache == "" {
		return "", false
	}
	dir := filepath.Join(gomodcache, escapeModulePath(modulePath)+"@"+version)
	for _, name := range licenseFilenames {
		full := filepath.Join(dir, name)
		if info, err := os.Stat(full); err == nil && !info.IsDir() {
			return full, true
		}
	}
	return "", false
}

func resolveGomodcache() string {
	if v := os.Getenv("GOMODCACHE"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "go", "pkg", "mod")
}

func attachLicense(c *cdx.Component, det LicenseDetection) {
	if det.SPDXID == "" {
		existing := []cdx.Property{}
		if c.Properties != nil {
			existing = *c.Properties
		}
		existing = append(existing, cdx.Property{Name: "pci-dss-mcp:license-status", Value: "unknown"})
		c.Properties = &existing
		return
	}
	confStr := strconv.FormatFloat(det.Confidence/100.0, 'f', 2, 64)
	evProps := []cdx.Property{
		{Name: "pci-dss-mcp:license-confidence", Value: confStr},
	}
	if det.SourcePath != "" {
		evProps = append(evProps, cdx.Property{Name: "pci-dss-mcp:license-source", Value: filepath.Base(det.SourcePath)})
	}
	c.Licenses = &cdx.Licenses{
		{License: &cdx.License{ID: det.SPDXID, Acknowledgement: cdx.LicenseAcknowledgementConcluded}},
	}
	c.Evidence = &cdx.Evidence{
		Licenses: &cdx.Licenses{
			{License: &cdx.License{ID: det.SPDXID, Acknowledgement: cdx.LicenseAcknowledgementConcluded, Properties: &evProps}},
		},
	}
}
