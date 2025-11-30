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
	// only beyond the 72-byte bcrypt limit do NOT cross-verify (i.e., each password
	// should only verify against its own hash).
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
	// always differ due to random salts, regardless of different passwords.

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

// TestMaxCostValidation tests that MaxCost (31) produces a valid hash.
// Note: This test is skipped in short mode because cost 31 is extremely slow.
func TestMaxCostValidation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping MaxCost test in short mode (cost 31 is very slow)")
	}

	password := []byte("testpassword")
	hash, err := gobcrypt.Generate(password, gobcrypt.MaxCost)
	if err != nil {
		t.Fatalf("Generate failed with MaxCost: %v", err)
	}

	// Verify the hash works
	if err := gobcrypt.Compare(hash, password); err != nil {
		t.Fatalf("Compare failed with MaxCost hash: %v", err)
	}

	// Verify the cost is correct
	cost, err := gobcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("Cost failed: %v", err)
	}
	if cost != gobcrypt.MaxCost {
		t.Errorf("Expected cost %d, got %d", gobcrypt.MaxCost, cost)
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

func TestStandardBcryptHashesNotSupported(t *testing.T) {
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

	// Generate a hash using our library - it should have $2b$ prefix
	hash, err := gobcrypt.Generate(password, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify the output has $2b$ prefix (testing that upgrade2aTo2b was applied)
	if len(hash) < 4 {
		t.Fatal("Hash too short")
	}
	prefix := string(hash[:4])
	if prefix != "$2b$" {
		t.Errorf("Expected prefix $2b$, got %s", prefix)
	}

	// Verify the hash works with Compare
	if err := gobcrypt.Compare(hash, password); err != nil {
		t.Errorf("Compare failed for hash with $2b$ prefix: %v", err)
	}

	// Test that the underlying bcrypt library generates $2a$ hashes by default,
	// which proves our upgrade2aTo2b function is working.
	// We use the pre-hashed password directly with standard bcrypt.
	preHashed := gobcrypt.PreHashPassword(password)
	standardHash, err := bcrypt.GenerateFromPassword(preHashed, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Standard bcrypt Generate failed: %v", err)
	}

	// The standard library produces $2a$ prefix
	if string(standardHash[:4]) != "$2a$" {
		t.Errorf("Expected standard bcrypt to produce $2a$ prefix, got %s", string(standardHash[:4]))
	}

	// Our library's output should be $2b$, proving the upgrade happened
	if string(hash[:4]) != "$2b$" {
		t.Errorf("Our library should produce $2b$ prefix, got %s", string(hash[:4]))
	}
}

// TestBackwardCompatibilityWithLegacyHashes tests backward compatibility with hashes
// created using the legacy RawStdEncoding (no padding) pre-hashing method.
func TestBackwardCompatibilityWithLegacyHashes(t *testing.T) {
	password := []byte("testpassword")

	// Simulate a legacy hash created with RawStdEncoding (no padding)
	legacyPreHashed := gobcrypt.PreHashPasswordLegacy(password)
	legacyHash, err := bcrypt.GenerateFromPassword(legacyPreHashed, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Failed to create legacy hash: %v", err)
	}

	// Our Compare function should be able to verify this legacy hash
	if err := gobcrypt.Compare(legacyHash, password); err != nil {
		t.Errorf("Compare should work with legacy hashes (RawStdEncoding): %v", err)
	}

	// Also verify new hashes work
	newHash, err := gobcrypt.Generate(password, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if err := gobcrypt.Compare(newHash, password); err != nil {
		t.Errorf("Compare should work with new hashes (StdEncoding): %v", err)
	}
}

func TestPasswordExactly72Bytes(t *testing.T) {
	// Test the boundary condition where the password is exactly at bcrypt's native limit.
	// This verifies that pre-hashing correctly handles passwords at bcrypt's native 72-byte limit.
	password72 := make([]byte, bcryptPasswordLimit)
	for i := 0; i < bcryptPasswordLimit; i++ {
		password72[i] = 'a'
	}

	hash, err := gobcrypt.Generate(password72, gobcrypt.MinCost)
	if err != nil {
		t.Fatalf("Generate failed for exactly 72-byte password: %v", err)
	}

	// Verify the password matches its hash
	if err := gobcrypt.Compare(hash, password72); err != nil {
		t.Errorf("Compare failed for exactly 72-byte password: %v", err)
	}

	// Verify a slightly different 72-byte password does NOT match
	password72Different := make([]byte, bcryptPasswordLimit)
	for i := 0; i < bcryptPasswordLimit-1; i++ {
		password72Different[i] = 'a'
	}
	password72Different[bcryptPasswordLimit-1] = 'b'

	if err := gobcrypt.Compare(hash, password72Different); err == nil {
		t.Error("Different 72-byte password should not verify against original hash")
	}
}
