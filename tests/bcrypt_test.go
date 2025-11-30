package tests

import (
	"errors"
	"testing"

	gobcrypt "github.com/fawwazid/go-bcrypt"

	"golang.org/x/crypto/bcrypt"
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

func TestLongPasswordDifferentiation(t *testing.T) {
	// Two passwords identical in first 72 bytes but different after
	pass1 := make([]byte, 73)
	pass2 := make([]byte, 73)
	for i := 0; i < 72; i++ {
		pass1[i] = 'x'
		pass2[i] = 'x'
	}
	pass1[72] = 'a'
	pass2[72] = 'b'

	hash1, err := gobcrypt.Generate(pass1, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed for pass1: %v", err)
	}
	hash2, err := gobcrypt.Generate(pass2, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed for pass2: %v", err)
	}

	// Verify each password works with its own hash
	if err := gobcrypt.Compare(hash1, pass1); err != nil {
		t.Errorf("Compare failed for pass1 with hash1: %v", err)
	}
	if err := gobcrypt.Compare(hash2, pass2); err != nil {
		t.Errorf("Compare failed for pass2 with hash2: %v", err)
	}

	// Verify they don't cross-verify (the key security property)
	if err := gobcrypt.Compare(hash1, pass2); err == nil {
		t.Error("Different passwords should not verify: pass2 verified with hash1")
	}
	if err := gobcrypt.Compare(hash2, pass1); err == nil {
		t.Error("Different passwords should not verify: pass1 verified with hash2")
	}
}

func TestCostValidation(t *testing.T) {
	// Cost too low should return an error
	_, err := gobcrypt.Generate([]byte("pass"), 4)
	if err == nil {
		t.Fatal("Expected error for cost below MinCost")
	}
	if !errors.Is(err, gobcrypt.ErrCostTooLow) {
		t.Errorf("Expected ErrCostTooLow, got %v", err)
	}

	// Cost at MinCost should work
	hash, err := gobcrypt.Generate([]byte("pass"), gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed with MinCost: %v", err)
	}

	// Verify the password still works after hashing
	if err := gobcrypt.Compare(hash, []byte("pass")); err != nil {
		t.Fatalf("Compare failed after Generate with MinCost: %v", err)
	}

	// Check max cost
	_, err = gobcrypt.Generate([]byte("pass"), 32)
	if err == nil {
		t.Error("Expected error for cost > 31")
	}
}

func TestCost(t *testing.T) {
	password := []byte("testpass")
	expectedCost := 12

	hash, err := gobcrypt.Generate(password, expectedCost)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	cost, err := gobcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("Cost failed: %v", err)
	}
	if cost != expectedCost {
		t.Errorf("Expected cost %d, got %d", expectedCost, cost)
	}

	// Test with invalid hash
	_, err = gobcrypt.Cost([]byte("invalid"))
	if err == nil {
		t.Error("Expected error for invalid hash")
	}
}

func TestNeedsRehash(t *testing.T) {
	password := []byte("test")
	hash, err := gobcrypt.Generate(password, 12)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Hash with cost 12 should need rehash when target is 14
	if !gobcrypt.NeedsRehash(hash, 14) {
		t.Error("Expected NeedsRehash to return true for cost 12 < 14")
	}

	// Hash with cost 12 should not need rehash when target is 12
	if gobcrypt.NeedsRehash(hash, 12) {
		t.Error("Expected NeedsRehash to return false for cost 12 >= 12")
	}

	// Hash with cost 12 should not need rehash when target is lower
	if gobcrypt.NeedsRehash(hash, 10) {
		t.Error("Expected NeedsRehash to return false for cost 12 >= 10")
	}

	// Invalid hash should need rehash
	if !gobcrypt.NeedsRehash([]byte("invalid"), 12) {
		t.Error("Expected NeedsRehash to return true for invalid hash")
	}
}

func TestStandardBcryptIncompatibility(t *testing.T) {
	password := []byte("testpassword")

	// Create a hash using standard bcrypt (without pre-hashing)
	standardHash, err := bcrypt.GenerateFromPassword(password, 12)
	if err != nil {
		t.Fatalf("Standard bcrypt Generate failed: %v", err)
	}

	// Our Compare function should NOT be able to verify standard bcrypt hashes
	// because we only use pre-hashed passwords (security-focused design)
	err = gobcrypt.Compare(standardHash, password)
	if err == nil {
		t.Error("Compare should NOT work with standard bcrypt hashes (pre-hashing is always required)")
	}

	// Verify that hashes from this library work correctly
	ourHash, err := gobcrypt.Generate(password, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if err := gobcrypt.Compare(ourHash, password); err != nil {
		t.Errorf("Compare should work with hashes from this library: %v", err)
	}
}
