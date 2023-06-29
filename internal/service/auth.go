package service

import (
	"authService/internal/config"
	"authService/internal/model"
	"context"
	"errors"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"time"
)

var (
	ErrRefreshTokenIsExpired        = errors.New("refresh token is expired")
	ErrRefreshTokenNotFound         = errors.New("refresh token not found")
	ErrRefreshTokenMismatch         = errors.New("refresh token mismatch")
	ErrUnexpectedTokenSigningMethod = errors.New("unexpected token signing method")
	ErrInvalidTokenClaims           = errors.New("invalid token claims")
)

// SessionStorage used to store sessions
type SessionStorage interface {
	LoadAndDelete(refreshToken string) (*model.Session, bool)
	Load(username string) (*model.Session, bool)
	SaveSession(session *model.Session)
	Delete(refreshToken string)
}

// Claim Jwt Claim struct
type Claim struct {
	Username string
	jwt.StandardClaims
}

type Auth struct {
	cfg            *config.JwtConfig
	sessionStorage SessionStorage
}

func NewAuthService(cfg *config.JwtConfig, sessionStorage SessionStorage) *Auth {
	return &Auth{cfg: cfg, sessionStorage: sessionStorage}
}

func (a *Auth) ValidateToken(accessToken string) error {
	token, err := jwt.ParseWithClaims(
		accessToken,
		&Claim{},
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, ErrUnexpectedTokenSigningMethod
			}

			return []byte(a.cfg.AccessTokenKey), nil
		},
	)
	if err != nil {
		log.Errorf("invalid token: %v", err)
		return err
	}
	_, ok := token.Claims.(*Claim)
	if !ok {
		return ErrInvalidTokenClaims
	}

	return nil
}

func (a *Auth) GenerateTokens(ctx context.Context, username string) (refreshToken, accessToken string, err error) {
	refreshToken = uuid.New().String()
	a.sessionStorage.SaveSession(&model.Session{
		RefreshToken: refreshToken,
		Username:     username,
		ExpiresAt:    time.Now().Add(a.cfg.RefreshTokenExpiration).Unix(),
	})
	accessToken, err = a.generateAccessToken(username, a.cfg.AccessTokenKey, time.Now().Add(a.cfg.AccessTokenExpiration).Unix())
	if err != nil {
		return "", "", err
	}

	return refreshToken, accessToken, nil
}

func (a *Auth) RefreshTokens(ctx context.Context, refreshToken, username string) (newRefreshToken, accessToken string, err error) {
	session, loaded := a.sessionStorage.LoadAndDelete(username)
	if !loaded {
		return "", "", ErrRefreshTokenNotFound
	}

	if refreshToken != session.RefreshToken {
		return "", "", ErrRefreshTokenMismatch
	}

	if session.ExpiresAt <= time.Now().Unix() {
		return "", "", ErrRefreshTokenIsExpired
	}

	return a.GenerateTokens(ctx, username)
}

func (a *Auth) generateAccessToken(username, key string, expiresAt int64) (string, error) {
	claims := Claim{
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: expiresAt,
		},
		Username: username,
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(key))
	if err != nil {
		log.Errorf("auth/ generateAccessToken/ error in SignedString for username %s: %v", username, err)
		return "", err
	}

	return token, nil
}
