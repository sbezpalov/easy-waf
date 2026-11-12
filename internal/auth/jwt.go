// Copyright 2026 Sergey Bezpalov
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SessionClaims is the management-session JWT. SessionVersion must match users.session_version.
type SessionClaims struct {
	SessionVersion int `json:"sv"`
	// StepUpAt is when the operator last confirmed their password in this
	// session, in Unix seconds. Absent until they do.
	StepUpAt int64 `json:"sua,omitempty"`
	jwt.RegisteredClaims
}

func (c *SessionClaims) stepUpTime() time.Time {
	if c.StepUpAt == 0 {
		return time.Time{}
	}
	return time.Unix(c.StepUpAt, 0)
}

// minSigningKeyLen bounds both signing and verification. Aligned with
// MinJWTSecretLen so a short key cannot verify forged sessions either.
const minSigningKeyLen = MinJWTSecretLen

// SignJWT issues an HS256 JWT for the given subject and session epoch.
func SignJWT(secret []byte, username string, sessionVersion int, ttl time.Duration) (string, error) {
	return signSession(secret, username, sessionVersion, time.Now().Add(ttl), 0)
}

// SignStepUpJWT reissues a session token with a password confirmation recorded.
// It keeps expiresAt, so confirming never extends the session.
func SignStepUpJWT(secret []byte, username string, sessionVersion int, expiresAt, stepUpAt time.Time) (string, error) {
	return signSession(secret, username, sessionVersion, expiresAt, stepUpAt.Unix())
}

func signSession(secret []byte, username string, sessionVersion int, expiresAt time.Time, stepUpAt int64) (string, error) {
	if len(secret) < minSigningKeyLen {
		return "", fmt.Errorf("jwt secret too short")
	}
	if sessionVersion < 1 {
		return "", fmt.Errorf("invalid session version")
	}
	claims := SessionClaims{
		SessionVersion: sessionVersion,
		StepUpAt:       stepUpAt,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   username,
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(secret)
}

// ParseJWT returns session claims or an error. Tokens without sv or exp fail closed.
func ParseJWT(secret []byte, token string) (*SessionClaims, error) {
	if len(secret) < minSigningKeyLen {
		return nil, fmt.Errorf("jwt secret too short")
	}
	t, err := jwt.ParseWithClaims(token, &SessionClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return secret, nil
	},
		// exp is otherwise validated only when present, so a signed token that
		// carries no exp claim would never expire.
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
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
