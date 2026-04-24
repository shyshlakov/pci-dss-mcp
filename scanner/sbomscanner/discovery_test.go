package sbomscanner

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestListModules_Fixture(t *testing.T) {
	t.Parallel()
	fixtureRoot, err := filepath.Abs(filepath.Join("..", "..", "testdata", "vulnerable-payment-service"))
	if err != nil {
		t.Fatal(err)
	}
	mods, err := listModules(fixtureRoot)
	if err != nil {
		t.Fatalf("listModules: %v", err)
	}
	if got := len(mods); got < 40 {
		t.Fatalf("module count: got %d want >=40", got)
	}
	for i, m := range mods {
		if m.Path == "" {
			t.Errorf("mod[%d] missing Path", i)
		}
		if m.Version == "" {
			t.Errorf("mod[%d] (%s) missing Version", i, m.Path)
		}
		if m.Sum == "" {
			t.Errorf("mod[%d] (%s@%s) missing Sum", i, m.Path, m.Version)
		}
		if m.Sum != "" && !strings.HasPrefix(m.Sum, "h1:") {
			t.Errorf("mod[%d] (%s) sum %q missing h1: prefix", i, m.Path, m.Sum)
		}
	}
}

func TestListModules_MissingDir(t *testing.T) {
	t.Parallel()
	if _, err := listModules("/does/not/exist"); err == nil {
		t.Fatal("expected error for missing dir, got nil")
	}
}

func TestHashFromH1Sum(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name:    "happy_path_gin",
			input:   "h1:nTuyha1TYqgedzytsKYqna+DfLos46nTv2ygFy86HFU=",
			wantLen: 64,
		},
		{
			name:    "missing_h1_prefix",
			input:   "nTuyha1TYqgedzytsKYqna+DfLos46nTv2ygFy86HFU=",
			wantErr: true,
		},
		{
			name:    "empty",
			input:   "",
			wantErr: true,
		},
		{
			name:    "bad_base64",
			input:   "h1:!!!not-base64!!!",
			wantErr: true,
		},
		{
			name:    "wrong_length",
			input:   "h1:" + "YWJj",
			wantErr: true,
		},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := hashFromH1Sum(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err mismatch: got %v wantErr=%v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if len(got) != tc.wantLen {
				t.Errorf("len(hex): got %d want %d", len(got), tc.wantLen)
			}
		})
	}
}

func TestBuildPURL(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name    string
		modPath string
		version string
		want    string
	}{
		{
			name:    "gin",
			modPath: "github.com/gin-gonic/gin",
			version: "v1.10.0",
			want:    "pkg:golang/github.com/gin-gonic/gin@v1.10.0",
		},
		{
			name:    "stdx",
			modPath: "golang.org/x/text",
			version: "v0.15.0",
			want:    "pkg:golang/golang.org/x/text@v0.15.0",
		},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := buildPURL(tc.modPath, tc.version); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestReadLicense_CacheMiss(t *testing.T) {
	t.Setenv("GOMODCACHE", t.TempDir())
	got := readLicense("github.com/does-not-exist/pkg", "v0.0.1")
	if got != "UNKNOWN-LICENSE" {
		t.Errorf("cache-miss: got %q want UNKNOWN-LICENSE", got)
	}
}

func TestEscapeModulePath(t *testing.T) {
	t.Parallel()
	tt := []struct {
		name string
		in   string
		want string
	}{
		{name: "lowercase", in: "github.com/gin-gonic/gin", want: "github.com/gin-gonic/gin"},
		{name: "mixed_case", in: "github.com/CycloneDX/cyclonedx-go", want: "github.com/!cyclone!d!x/cyclonedx-go"},
		{name: "burnt_sushi", in: "github.com/BurntSushi/toml", want: "github.com/!burnt!sushi/toml"},
	}
	for _, tc := range tt {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := escapeModulePath(tc.in); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
