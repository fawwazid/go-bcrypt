package gobcrypt

import (
	"bytes"
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

func TestNeedsPrehash(t *testing.T) {
	atLimit := bytes.Repeat([]byte("a"), PasswordLimit)    // exactly PasswordLimit bytes
	overLimit := append(append([]byte{}, atLimit...), 'b') // PasswordLimit + 1 bytes
	if needsPrehash(atLimit) {
		t.Fatalf("needsPrehash returned true for password at PasswordLimit (%d bytes)", PasswordLimit)
	}
	if !needsPrehash(overLimit) {
		t.Fatalf("needsPrehash returned false for password over PasswordLimit (%d bytes)", PasswordLimit+1)
	}
}
