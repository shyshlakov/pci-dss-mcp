package tokens

import "net/http"

func TokenizeCardExchange(w http.ResponseWriter, r *http.Request) {
	if err := exchangeWork(r); err != nil {
		w.Write([]byte(err.Error()))
		return
	}
	w.WriteHeader(http.StatusOK)
}

func exchangeWork(_ *http.Request) error { return nil }
