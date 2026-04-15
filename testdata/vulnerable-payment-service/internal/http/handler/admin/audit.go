package admin

import (
	"fmt"
	"net/http"
)

func GetLogs(w http.ResponseWriter, r *http.Request) {
	fmt.Println("logs requested by", r.RemoteAddr)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("[]"))
}
