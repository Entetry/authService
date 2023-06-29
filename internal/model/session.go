// Package model provides domain models
package model

// Session refresh session token struct
type Session struct {
	RefreshToken string
	Username     string
	ExpiresAt    int64
}
