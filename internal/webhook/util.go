package webhook

import (
	"crypto/x509"
	"fmt"
	"os"
)

func loadCABundle(path string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA %s: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("CA bundle empty/invalid: %s", path)
	}
	return pool, nil
}
