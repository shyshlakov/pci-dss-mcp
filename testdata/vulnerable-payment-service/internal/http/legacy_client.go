package http

import (
	"crypto/tls"
	stdhttp "net/http"
)

var LegacyClient = &stdhttp.Client{
	Transport: &stdhttp.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS10,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_RC4_128_SHA,
			},
		},
	},
}
