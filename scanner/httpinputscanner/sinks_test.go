package httpinputscanner

import (
	"testing"
)

func TestLogSinkLibraryCoverage(t *testing.T) {
	required := []struct {
		pkg    string
		typ    string
		method string
	}{
		{pkg: "log/slog", typ: "Logger", method: "Info"},
		{pkg: "log/slog", typ: "Logger", method: "Error"},
		{pkg: "log/slog", typ: "Logger", method: "ErrorContext"},
		{pkg: "log/slog", method: "Info"},
		{pkg: "log/slog", method: "Error"},
		{pkg: "log/slog", method: "String"},
		{pkg: "log/slog", method: "Any"},
		{pkg: "log/slog", method: "Group"},
		{pkg: "log", method: "Print"},
		{pkg: "log", method: "Printf"},
		{pkg: "github.com/sirupsen/logrus", method: "Info"},
		{pkg: "github.com/sirupsen/logrus", method: "WithFields"},
		{pkg: "github.com/sirupsen/logrus", typ: "Entry", method: "Info"},
		{pkg: "go.uber.org/zap", typ: "Logger", method: "Info"},
		{pkg: "github.com/rs/zerolog", typ: "Event", method: "Msg"},
		{pkg: "github.com/rs/zerolog", typ: "Event", method: "Send"},
		{pkg: "github.com/rs/zerolog", typ: "Event", method: "Str"},
		{pkg: "github.com/go-logr/logr", typ: "Logger", method: "Info"},
		{pkg: "k8s.io/klog/v2", method: "InfoS"},
		{pkg: "github.com/hashicorp/go-hclog", typ: "Logger", method: "Info"},
	}
	for _, want := range required {
		t.Run(want.pkg+"/"+want.typ+"/"+want.method, func(t *testing.T) {
			found := false
			for _, spec := range logSinkLibrary {
				if spec.PkgPath == want.pkg && spec.TypeName == want.typ && spec.Method == want.method {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("logSinkLibrary missing %s.%s.%s", want.pkg, want.typ, want.method)
			}
		})
	}
}

func TestSinkDisplayName(t *testing.T) {
	tt := []struct {
		pkg    string
		recv   string
		method string
		want   string
	}{
		{pkg: "log/slog", recv: "Logger", method: "Info", want: "slog.Info"},
		{pkg: "log", recv: "Logger", method: "Print", want: "log.Print"},
		{pkg: "github.com/sirupsen/logrus", recv: "Entry", method: "Error", want: "logrus.Error"},
		{pkg: "go.uber.org/zap", recv: "Logger", method: "Info", want: "zap.Info"},
		{pkg: "github.com/rs/zerolog", recv: "Event", method: "Send", want: "zerolog.Send"},
		{pkg: "k8s.io/klog/v2", method: "Info", want: "klog.Info"},
	}
	for _, tc := range tt {
		t.Run(tc.want, func(t *testing.T) {
			if got := sinkDisplayName(tc.pkg, tc.recv, tc.method); got != tc.want {
				t.Fatalf("sinkDisplayName(%q,%q,%q) = %q, want %q", tc.pkg, tc.recv, tc.method, got, tc.want)
			}
		})
	}
}
