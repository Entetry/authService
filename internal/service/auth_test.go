package service

import (
	"context"
	"github.com/Entetry/authService/internal/config"
	"github.com/Entetry/authService/internal/model"
	"github.com/Entetry/authService/internal/service/mocks"
	"github.com/stretchr/testify/mock"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var (
	mockAccessTokenKey = "mock-access-token-key"
	mockRefreshToken   = "mock-refresh-token"
	mockUsername       = "test_user"
	mockExpiresAt      = time.Now().Add(24 * time.Hour).Unix()
	session            = model.Session{
		RefreshToken: mockRefreshToken,
		Username:     mockUsername,
		ExpiresAt:    mockExpiresAt,
	}
	cfg = config.JwtConfig{
		AccessTokenKey:         mockAccessTokenKey,
		AccessTokenExpiration:  30 * time.Minute,
		RefreshTokenExpiration: 24 * time.Hour,
	}
)

func TestAuth_GenerateTokens(t *testing.T) {
	mockSessionStorage := mocks.NewSessionStorage(t)
	auth := NewAuthService(&cfg, mockSessionStorage, nil)
	mockSessionStorage.On("SaveSession", mock.AnythingOfType("*model.Session")).Return()
	refreshToken, accessToken, err := auth.GenerateTokens(context.Background(), mockUsername)

	assert.NoError(t, err, "Expected no error when generating tokens")
	assert.NotEmpty(t, refreshToken, "Expected a non-empty refresh token")
	assert.NotEmpty(t, accessToken, "Expected a non-empty access token")
}

func TestAuth_RefreshTokens(t *testing.T) {
	mockSessionStorage := mocks.NewSessionStorage(t)
	auth := NewAuthService(&cfg, mockSessionStorage, nil)

	mockSessionStorage.On("LoadAndDelete", mockUsername).Return(&session, true)
	mockSessionStorage.On("SaveSession", mock.AnythingOfType("*model.Session"))

	newRefreshToken, accessToken, err := auth.RefreshTokens(context.Background(), mockRefreshToken, mockUsername)

	assert.NoError(t, err, "Expected no error when refreshing tokens")
	assert.NotEmpty(t, newRefreshToken, "Expected a non-empty new refresh token")
	assert.NotEmpty(t, accessToken, "Expected a non-empty access token")
	mockSessionStorage.AssertExpectations(t)
}

func TestAuth_RefreshTokens_ExpiredRefreshToken(t *testing.T) {
	mockSessionStorage := mocks.NewSessionStorage(t)
	auth := NewAuthService(&cfg, mockSessionStorage, nil)
	expiredSession := model.Session{
		RefreshToken: mockRefreshToken,
		Username:     mockUsername,
		ExpiresAt:    time.Now().Add(-1 * time.Hour).Unix(),
	}
	mockSessionStorage.On("LoadAndDelete", mockUsername).Return(&expiredSession, true)

	newRefreshToken, accessToken, err := auth.RefreshTokens(context.Background(), mockRefreshToken, mockUsername)

	assert.EqualError(t, err, ErrRefreshTokenIsExpired.Error(), "Expected ErrRefreshTokenIsExpired for an expired refresh token")
	assert.Empty(t, newRefreshToken, "Expected an empty new refresh token")
	assert.Empty(t, accessToken, "Expected an empty access token")
	mockSessionStorage.AssertExpectations(t)
}
