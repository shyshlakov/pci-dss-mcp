package util

import (
	"fmt"
	"os"
)

func WriteToFile(f *os.File, data []byte) error {
	_, err := f.Write(data)
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}
