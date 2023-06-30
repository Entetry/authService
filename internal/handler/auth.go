// Package handler contains grpc endpoints
package handler

import (
	"context"
	"errors"
	"github.com/Entetry/authService/internal/service"
	"github.com/Entetry/authService/protocol/authService"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Auth handler struct
type Auth struct {
	authService.UnsafeAuthGRPCServiceServer
	auth *service.Auth
}

// NewAuth creates new auth handler
func NewAuth(auth *service.Auth) *Auth {
	return &Auth{auth: auth}
}

// ValidateTokens validate jwt tokens endpoint
func (a *Auth) ValidateTokens(ctx context.Context, request *authService.ValidateTokensRequest) (*authService.ValidateTokensResponse, error) {
	err := a.auth.ValidateToken(request.AccessToken)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	return &authService.ValidateTokensResponse{}, nil
}

// RefreshTokens Refresh update tokens
func (a *Auth) RefreshTokens(ctx context.Context, request *authService.RefreshTokensRequest) (*authService.RefreshTokensResponse, error) {
	refreshToken, accessToken, err := a.auth.RefreshTokens(ctx, request.RefreshToken, request.Username)
	if errors.Is(err, service.ErrRefreshTokenNotFound) {
		return nil, status.Error(codes.NotFound, err.Error())
	} else if errors.Is(err, service.ErrRefreshTokenMismatch) || errors.Is(err, service.ErrRefreshTokenIsExpired) {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authService.RefreshTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// GenerateTokens generate access and refresh tokens
func (a *Auth) GenerateTokens(ctx context.Context, request *authService.GenerateTokensRequest) (*authService.GenerateTokensResponse, error) {
	refreshToken, accessToken, err := a.auth.GenerateTokens(ctx, request.Username)
	if err != nil {
		log.Error(err)
		return nil, status.Error(codes.Internal, err.Error())
	}

	return &authService.GenerateTokensResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// SignUp sign up
func (a *Auth) SignUp(ctx context.Context, request *authService.SignUpRequest) (*authService.SignUpResponse, error) {
	err := a.auth.SignUp(ctx, request.Username, request.Password, request.Email)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	return &authService.SignUpResponse{}, nil
}

// SignIn sign in
func (a *Auth) SignIn(ctx context.Context, request *authService.SignInRequest) (*authService.SignInResponse, error) {
	refreshToken, accessToken, err := a.auth.SignIn(ctx, request.Username, request.Password)
	if errors.Is(err, service.ErrInvalidPassword) {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}
	return &authService.SignInResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
