package tests

import (
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

func TestCostValidation(t *testing.T) {
	hash, err := gobcrypt.Generate([]byte("pass"), 4) // Too low, should default to DefaultCost (14)
	if err != nil {
		t.Fatalf("Generate failed with low cost: %v", err)
	}

	// Verify that the cost was actually upgraded to DefaultCost
	actualCost, err := gobcrypt.Cost(hash)
	if err != nil {
		t.Fatalf("Cost failed: %v", err)
	}
	if actualCost != gobcrypt.DefaultCost {
		t.Errorf("Expected cost %d for low cost input, got %d", gobcrypt.DefaultCost, actualCost)
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

func TestStandardBcryptCompatibility(t *testing.T) {
	password := []byte("testpassword")

	// Create a hash using standard bcrypt (without pre-hashing)
	standardHash, err := bcrypt.GenerateFromPassword(password, 12)
	if err != nil {
		t.Fatalf("Standard bcrypt Generate failed: %v", err)
	}

	// Our Compare function should be able to verify standard bcrypt hashes
	err = gobcrypt.Compare(standardHash, password)
	if err != nil {
		t.Errorf("Compare should work with standard bcrypt hashes: %v", err)
	}

	// Verify wrong password still fails
	err = gobcrypt.Compare(standardHash, []byte("wrongpassword"))
	if err == nil {
		t.Error("Compare should fail with wrong password for standard bcrypt hash")
	}
}
