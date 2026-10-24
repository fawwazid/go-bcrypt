package gobcrypt

import (
	"crypto/fips140"
	"errors"
	"testing"
)

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	for _, operation := range []func() error{
		func() error { _, err := Generate([]byte("password"), MinCost); return err },
		func() error { return Compare([]byte("invalid"), []byte("password")) },
	} {
		if err := operation(); !errors.Is(err, ErrFIPSUnsupported) {
			t.Fatalf("operation error = %v", err)
		}
	}
}
