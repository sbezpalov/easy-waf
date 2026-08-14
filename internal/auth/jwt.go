package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionClaims is the management-session JWT. SessionVersion must match users.session_version.
type SessionClaims struct {
	SessionVersion int `json:"sv"`
	jwt.RegisteredClaims
}

// SignJWT issues an HS256 JWT for the given subject and session epoch.
func SignJWT(secret []byte, username string, sessionVersion int, ttl time.Duration) (string, error) {
	if len(secret) < 16 {
		return "", fmt.Errorf("jwt secret too short")
	}
	if sessionVersion < 1 {
		return "", fmt.Errorf("invalid session version")
	}
	now := time.Now()
	claims := SessionClaims{
		SessionVersion: sessionVersion,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}

// ParseJWT returns session claims or an error. Tokens without sv fail closed.
func ParseJWT(secret []byte, token string) (*SessionClaims, error) {
	t, err := jwt.ParseWithClaims(token, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := t.Claims.(*SessionClaims)
	if !ok || !t.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("empty subject")
	}
	if claims.SessionVersion < 1 {
		return nil, fmt.Errorf("missing session version")
	}
	return claims, nil
}

// SessionMatches reports whether the JWT epoch matches the stored user epoch.
func SessionMatches(tokenVersion, userVersion int) bool {
	return tokenVersion >= 1 && tokenVersion == userVersion
}
