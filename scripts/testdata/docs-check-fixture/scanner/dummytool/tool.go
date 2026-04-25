package dummytool

type DummyInput struct {
	Path   string `json:"path"`
	Format string `json:"format"`
}

const ErrUnknown = "OK_TOKEN"
