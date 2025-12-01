package gobcrypt

import (
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
	})

	t.Run("CostTooHigh", func(t *testing.T) {
		cost := MaxCost + 1
		_, err := Generate(password, cost)
		if err == nil {
			t.Error("Expected error for cost too high, got nil")
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
	})

	t.Run("EmptyHash", func(t *testing.T) {
		err := Compare([]byte{}, password)
		if err != ErrHashEmpty {
			t.Errorf("Expected ErrHashEmpty, got %v", err)
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
