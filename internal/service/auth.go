package service

import (
	"context"
	"errors"
	"github.com/Entetry/authService/internal/config"
	"github.com/Entetry/authService/internal/model"
	"github.com/Entetry/userService/protocol/userService"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"time"
)

var (
	ErrRefreshTokenIsExpired        = errors.New("refresh token is expired")
	ErrRefreshTokenNotFound         = errors.New("refresh token not found")
	ErrRefreshTokenMismatch         = errors.New("refresh token mismatch")
	ErrUnexpectedTokenSigningMethod = errors.New("unexpected token signing method")
	ErrInvalidTokenClaims           = errors.New("invalid token claims")
	ErrInvalidPassword              = errors.New("invalid token claims")
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

// Auth service struct
type Auth struct {
	cfg               *config.JwtConfig
	sessionStorage    SessionStorage
	userServiceClient userService.UserServiceClient
}

// NewAuthService creates new Auth service
func NewAuthService(
	cfg *config.JwtConfig, sessionStorage SessionStorage, userServiceClient userService.UserServiceClient) *Auth {
	return &Auth{cfg: cfg, sessionStorage: sessionStorage, userServiceClient: userServiceClient}
}

// SignUp sign up user
func (a *Auth) SignUp(ctx context.Context, username, pwd, email string) error {
	_, err := a.userServiceClient.Create(ctx, &userService.CreateRequest{
		Username: username,
		Email:    email,
		Password: pwd,
	})
	return err
}

// SignIn sign in user
func (a *Auth) SignIn(ctx context.Context, username, pwd string) (refreshToken string, accessToken string, err error) {
	user, err := a.userServiceClient.GetByUsername(ctx, &userService.GetByUsernameRequest{
		Username: username,
	})
	if err != nil {
		log.Error("Auth / SignIn /GetByUsername err %w ", err)
		return "", "", err
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(pwd))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return "", "", ErrInvalidPassword
	} else if err != nil {
		log.Errorf("SignIn / CompareHashAndPassword / error %w", err)
		return "", "", err
	}

	return a.GenerateTokens(ctx, username)
}

// ValidateToken validate token
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

// GenerateTokens generate token
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

// RefreshTokens refresh tokens
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
