package gobcrypt

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestGenerate(t *testing.T) {
	password := []byte("password123")

	t.Run("ValidCost", func(t *testing.T) {
		cost := 14
		hash, err := Generate(password, cost)
		if err != nil {
			t.Fatalf("Generate failed: %v", err)
		}
		if len(hash) == 0 {
			t.Error("Expected hash, got empty byte slice")
		}

		// Verify the cost matches
		actualCost, err := bcrypt.Cost(hash)
		if err != nil {
			t.Fatalf("Failed to get cost from hash: %v", err)
		}
		if actualCost != cost {
			t.Errorf("Expected cost %d, got %d", cost, actualCost)
		}
	})

	t.Run("CostTooLow", func(t *testing.T) {
		cost := MinCost - 1
		_, err := Generate(password, cost)
		if err == nil {
			t.Error("Expected error for cost too low, got nil")
		}
		if !errors.Is(err, ErrCostTooLow) {
			t.Errorf("expected ErrCostTooLow, got %v", err)
		}
	})

	t.Run("CostTooHigh", func(t *testing.T) {
		cost := MaxCost + 1
		_, err := Generate(password, cost)
		if err == nil {
			t.Error("Expected error for cost too high, got nil")
		}
		if !errors.Is(err, ErrCostTooHigh) {
			t.Errorf("expected ErrCostTooHigh, got %v", err)
		}
	})
}

func TestCompare(t *testing.T) {
	password := []byte("password123")
	cost := 12
	hash, err := Generate(password, cost)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	t.Run("Match", func(t *testing.T) {
		err := Compare(hash, password)
		if err != nil {
			t.Errorf("Expected match, got error: %v", err)
		}
	})

	t.Run("NoMatch", func(t *testing.T) {
		wrongPassword := []byte("wrongpassword")
		err := Compare(hash, wrongPassword)
		if err == nil {
			t.Error("Expected error for wrong password, got nil")
		}
		if !errors.Is(err, ErrCompareFailed) {
			t.Errorf("expected ErrCompareFailed for mismatch, got %v", err)
		}
	})

	t.Run("EmptyHash", func(t *testing.T) {
		err := Compare([]byte{}, password)
		if !errors.Is(err, ErrHashEmpty) {
			t.Errorf("Expected ErrHashEmpty, got %v", err)
		}
	})

	t.Run("EmptyPassword", func(t *testing.T) {
		empty := []byte("")
		h, err := Generate(empty, DefaultCost)
		if err != nil {
			t.Fatalf("Generate(empty) failed: %v", err)
		}
		if err := Compare(h, empty); err != nil {
			t.Errorf("Expected empty password to match its hash, got %v", err)
		}
	})

	t.Run("PasswordLengthBoundary", func(t *testing.T) {
		// Passwords longer than PasswordLimit have bytes beyond that ignored by bcrypt.
		p72 := bytes.Repeat([]byte("a"), PasswordLimit)
		p73 := append(append([]byte{}, p72...), 'b')

		h72, err := Generate(p72, DefaultCost)
		if err != nil {
			t.Fatalf("Generate(p72) failed: %v", err)
		}

		// With pre-hashing enabled for long passwords, a 73-byte password is
		// not silently truncated. Therefore, comparing the hash of a 72-byte
		// password with a 73-byte password that differs after the 72nd byte
		// should now fail.
		if err := Compare(h72, p73); err == nil {
			t.Errorf("Expected Compare(h72, p73) to fail due to pre-hash behavior")
		}

		// Generating a hash from a password longer than PasswordLimit should
		// succeed because we pre-hash long inputs before passing them to
		// bcrypt.
		h73, err := Generate(p73, DefaultCost)
		if err != nil {
			t.Fatalf("Generate(p73) failed: %v", err)
		}

		// And the generated hash should validate with the original long password.
		if err := Compare(h73, p73); err != nil {
			t.Errorf("Expected Compare(h73, p73) to succeed, got %v", err)
		}
	})
}

func TestCost(t *testing.T) {
	password := []byte("password123")
	targetCost := 13
	hash, err := Generate(password, targetCost)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	t.Run("ValidHash", func(t *testing.T) {
		c, err := Cost(hash)
		if err != nil {
			t.Errorf("Expected no error, got %v", err)
		}
		if c != targetCost {
			t.Errorf("Expected cost %d, got %d", targetCost, c)
		}
	})

	t.Run("InvalidHash", func(t *testing.T) {
		_, err := Cost([]byte("invalid-hash"))
		if err == nil {
			t.Error("Expected error for invalid hash, got nil")
		}
	})
}

func TestNeedsRehash(t *testing.T) {
	password := []byte("password123")

	t.Run("NeedsUpgrade", func(t *testing.T) {
		lowCost := MinCost
		hash, err := Generate(password, lowCost)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		targetCost := lowCost + 1
		if !NeedsRehash(hash, targetCost) {
			t.Error("Expected NeedsRehash to return true")
		}
	})

	t.Run("NoUpgradeNeeded", func(t *testing.T) {
		highCost := MinCost + 2
		hash, err := Generate(password, highCost)
		if err != nil {
			t.Fatalf("Setup failed: %v", err)
		}

		targetCost := highCost // Same cost
		if NeedsRehash(hash, targetCost) {
			t.Error("Expected NeedsRehash to return false for same cost")
		}

		targetCost = highCost - 1 // Lower target
		if NeedsRehash(hash, targetCost) {
			t.Error("Expected NeedsRehash to return false for lower target cost")
		}
	})

	t.Run("InvalidHash", func(t *testing.T) {
		if !NeedsRehash([]byte("invalid"), 14) {
			t.Error("Expected NeedsRehash to return true for invalid hash (fail safe)")
		}
	})
}
