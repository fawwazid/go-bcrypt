package gobcrypt

import (
	"errors"
	"testing"
)

func TestRejectsExcessiveStoredCost(t *testing.T) {
	// A syntactically valid hash with cost 31 must be rejected before bcrypt work.
	hash := []byte("$2a$31$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
	if err := Compare(hash, []byte("password")); !errors.Is(err, ErrCostTooHigh) {
		t.Fatalf("error = %v", err)
	}
}

func TestRejectsWeakStoredCost(t *testing.T) {
	hash := []byte("$2a$04$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
	if err := Compare(hash, []byte("password")); !errors.Is(err, ErrCostTooLow) {
		t.Fatalf("error = %v", err)
	}
}
