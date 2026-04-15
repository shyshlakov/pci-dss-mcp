package tokens

import (
	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/shyshlakov/pci-dss-mcp/testdata/vulnerable-payment-service/internal/http/middleware"
)

func Tokenize(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")

	logrus.WithFields(logrus.Fields{
		middleware.LogKeyRequestID: requestID,
		middleware.LogKeyEventType: "tokenize_attempt",
		"http.status":              http.StatusOK,
	}).Info("tokenize request received")

	if err := callPSP(r); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func callPSP(_ *http.Request) error { return nil }
