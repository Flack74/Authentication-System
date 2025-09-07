package utils

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "testpassword123"
	cost := 12

	hash, err := HashPassword(password, cost)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == "" {
		t.Fatal("Hash should not be empty")
	}

	if hash == password {
		t.Fatal("Hash should not equal original password")
	}
}

func TestCheckPassword(t *testing.T) {
	password := "testpassword123"
	cost := 12

	hash, err := HashPassword(password, cost)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Test correct password
	err = CheckPassword(password, hash)
	if err != nil {
		t.Fatalf("CheckPassword failed for correct password: %v", err)
	}

	// Test incorrect password
	err = CheckPassword("wrongpassword", hash)
	if err == nil {
		t.Fatal("CheckPassword should fail for incorrect password")
	}
}