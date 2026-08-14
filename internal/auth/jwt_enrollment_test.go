package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestSignParseJWT_sessionVersion(t *testing.T) {
	secret := []byte("0123456789abcdef")
	tok, err := SignJWT(secret, "admin", 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseJWT(secret, tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject != "admin" || c.SessionVersion != 2 {
		t.Fatalf("claims %+v", c)
	}
	if !SessionMatches(c.SessionVersion, 2) {
		t.Fatal("expected match")
	}
	if SessionMatches(c.SessionVersion, 3) {
		t.Fatal("stale session must not match")
	}
}

func TestParseJWT_missingSessionVersionFailsClosed(t *testing.T) {
	secret := []byte("0123456789abcdef")
	claims := jwt.RegisteredClaims{
		Subject:   "admin",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseJWT(secret, tok); err == nil {
		t.Fatal("legacy token without sv must fail closed")
	}
}
