package http_input

type Bundle struct{}

func NewBundle() *Bundle { return &Bundle{} }

func (b *Bundle) Mask(in []byte) []byte { return []byte("***") }

func Maskify(s string) string { return "***" }
