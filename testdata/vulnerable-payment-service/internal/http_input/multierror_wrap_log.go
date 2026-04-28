package http_input

import (
	"fmt"
	"log/slog"
	"net/http"

	multierror "github.com/hashicorp/go-multierror"
)

func MultierrorWrapLog(w http.ResponseWriter, r *http.Request) {
	var errs *multierror.Error
	pathErr := fmt.Errorf("path: %q", r.URL.Path)
	errs = multierror.Append(errs, pathErr)
	slog.Error("multi-error",
		slog.String("err", errs.Error()),
	)
	w.WriteHeader(http.StatusBadRequest)
}
