package tests

import (
	"errors"
	"testing"

	gobcrypt "github.com/fawwazid/go-bcrypt"

	"golang.org/x/crypto/bcrypt"
)

// bcryptPasswordLimit is the maximum password length that bcrypt can process.
// Passwords longer than this have bytes beyond the 72nd byte ignored by standard bcrypt.
const bcryptPasswordLimit = 72

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
	// This test verifies that the SHA-256 pre-hashing ensures passwords differing
	// only beyond the 72-byte bcrypt limit produce different verification results.
	// Without pre-hashing, bcrypt would truncate both passwords and treat them as equal.
	
	// Two passwords identical in first bcryptPasswordLimit bytes but different after
	pass1 := make([]byte, bcryptPasswordLimit+1)
	pass2 := make([]byte, bcryptPasswordLimit+1)
	for i := 0; i < bcryptPasswordLimit; i++ {
		pass1[i] = 'x'
		pass2[i] = 'x'
	}
	pass1[bcryptPasswordLimit] = 'a'
	pass2[bcryptPasswordLimit] = 'b'

	hash1, err := gobcrypt.Generate(pass1, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed for pass1: %v", err)
	}
	hash2, err := gobcrypt.Generate(pass2, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed for pass2: %v", err)
	}

	// Note: We don't compare the hashes directly because bcrypt hashes will
	// always differ due to random salts, regardless of password differences.

	// Verify each password works with its own hash
	if err := gobcrypt.Compare(hash1, pass1); err != nil {
		t.Errorf("Compare failed for pass1 with hash1: %v", err)
	}
	if err := gobcrypt.Compare(hash2, pass2); err != nil {
		t.Errorf("Compare failed for pass2 with hash2: %v", err)
	}

	// The key security property: passwords that differ only beyond 72 bytes
	// should NOT cross-verify. This proves SHA-256 pre-hashing is working.
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

func TestEmptyPassword(t *testing.T) {
	// Test that empty passwords are handled correctly
	emptyPassword := []byte{}

	hash, err := gobcrypt.Generate(emptyPassword, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed for empty password: %v", err)
	}

	// Verify the empty password matches its hash
	if err := gobcrypt.Compare(hash, emptyPassword); err != nil {
		t.Errorf("Compare failed for empty password: %v", err)
	}

	// Verify a non-empty password does NOT match the empty password hash
	if err := gobcrypt.Compare(hash, []byte("notEmpty")); err == nil {
		t.Error("Non-empty password should not verify against empty password hash")
	}
}

func TestUpgrade2aTo2b(t *testing.T) {
	password := []byte("testpassword")

	// Generate a hash and verify it has $2b$ prefix
	hash, err := gobcrypt.Generate(password, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Check that the prefix is $2b$
	if len(hash) < 4 {
		t.Fatal("Hash too short")
	}
	prefix := string(hash[:4])
	if prefix != "$2b$" {
		t.Errorf("Expected prefix $2b$, got %s", prefix)
	}

	// Verify the hash still works with Compare
	if err := gobcrypt.Compare(hash, password); err != nil {
		t.Errorf("Compare failed for hash with $2b$ prefix: %v", err)
	}

	// Manually create a hash with $2a$ prefix and verify it still works with Compare
	// (since bcrypt can verify both $2a$ and $2b$ prefixes)
	hashWithA := make([]byte, len(hash))
	copy(hashWithA, hash)
	hashWithA[2] = 'a' // Change $2b$ to $2a$

	// Verify Compare still works with $2a$ prefix (bcrypt handles both)
	if err := gobcrypt.Compare(hashWithA, password); err != nil {
		t.Errorf("Compare should work with $2a$ prefix: %v", err)
	}
}
