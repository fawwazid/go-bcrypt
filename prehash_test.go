package gobcrypt

import (
	"bytes"
	"errors"
	"testing"
)

func TestPrehashDeterministic(t *testing.T) {
	p := []byte("this is a very long password that exceeds the bcrypt limit and should be prehashed")
	h1 := Prehash(p)
	h2 := Prehash(p)
	if !bytes.Equal(h1, h2) {
		t.Fatalf("Prehash not deterministic: %x != %x", h1, h2)
	}
	if len(h1) != 32 {
		t.Fatalf("Expected SHA-256 length 32, got %d", len(h1))
	}
}

func TestLegacyPrehashMigration(t *testing.T) {
	password := bytes.Repeat([]byte("a"), PasswordLimit+1)
	hash, err := Generate(Prehash(password), MinCost)
	if err != nil {
		t.Fatalf("Generate legacy pre-hash: %v", err)
	}

	if err := Compare(hash, password); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("expected direct comparison to reject long password, got %v", err)
	}
	if err := Compare(hash, Prehash(password)); err != nil {
		t.Fatalf("compare legacy pre-hash: %v", err)
	}
}
