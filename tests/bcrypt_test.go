package tests

import (
	"testing"

	gobcrypt "github.com/fawwazid/go-bcrypt"
)

func TestGenerateAndCompare(t *testing.T) {
	password := []byte("mysecretpassword")

	// Test with default cost (which should be >= 12)
	hash, err := gobcrypt.Generate(password, gobcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check prefix
	if string(hash[:4]) != "$2b$" {
		t.Errorf("Expected prefix $2b$, got %s", string(hash[:4]))
	}

	// Verify
	err = gobcrypt.Compare(hash, password)
	if err != nil {
		t.Errorf("Compare failed: %v", err)
	}

	// Verify with wrong password
	err = gobcrypt.Compare(hash, []byte("wrongpassword"))
	if err == nil {
		t.Error("Compare should have failed with wrong password")
	}
}

func TestLongPassword(t *testing.T) {
	// Password longer than 72 bytes
	longPass := make([]byte, 100)
	for i := range longPass {
		longPass[i] = 'a'
	}

	hash, err := gobcrypt.Generate(longPass, gobcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("Generate failed for long password: %v", err)
	}

	err = gobcrypt.Compare(hash, longPass)
	if err != nil {
		t.Errorf("Compare failed for long password: %v", err)
	}
}

func TestCostValidation(t *testing.T) {
	_, err := gobcrypt.Generate([]byte("pass"), 4) // Too low, should default to DefaultCost (14)
	if err != nil {
		t.Fatalf("Generate failed with low cost: %v", err)
	}
	// We can't easily check the cost used without parsing, but Generate handles it.

	// Check max cost
	_, err = gobcrypt.Generate([]byte("pass"), 32)
	if err == nil {
		t.Error("Expected error for cost > 31")
	}
}
