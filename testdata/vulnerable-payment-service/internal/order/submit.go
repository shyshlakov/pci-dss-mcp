package order

type Request struct {
	PAN string `json:"pan"`
}

func Submit(req *Request) string {
	return req.PAN
}
