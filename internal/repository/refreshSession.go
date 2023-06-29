// Package repository contains cache access methods
package repository

import (
	"github.com/Entetry/authService/internal/model"
	"sync"
)

// RefreshSessionStorage RefreshSession Refresh Session service struct
type RefreshSessionStorage struct {
	refreshTokenStorage *sync.Map
}

// NewRefreshSessionStorage creates new Refresh Session service
func NewRefreshSessionStorage(refreshTokenStorage *sync.Map) *RefreshSessionStorage {
	return &RefreshSessionStorage{
		refreshTokenStorage: refreshTokenStorage}
}

// LoadAndDelete gets refresh session and removes it from cash
func (r *RefreshSessionStorage) LoadAndDelete(username string) (*model.Session, bool) {
	session, ok := r.refreshTokenStorage.LoadAndDelete(username)
	if !ok {
		return nil, ok
	}
	return session.(*model.Session), ok
}

// SaveSession save refresh session to db( delete all sessions if user has >5 sessions)
func (r *RefreshSessionStorage) SaveSession(session *model.Session) {
	r.refreshTokenStorage.Store(session.Username, session)
}

// Delete delete refresh session by token
func (r *RefreshSessionStorage) Delete(username string) {
	r.refreshTokenStorage.Delete(username)
}

// Load gets refresh session and removes it from cash
func (r *RefreshSessionStorage) Load(username string) (*model.Session, bool) {
	session, ok := r.refreshTokenStorage.Load(username)
	if !ok {
		return nil, ok
	}
	return session.(*model.Session), ok
}
