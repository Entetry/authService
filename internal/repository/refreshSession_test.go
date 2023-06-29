package repository

import (
	"authService/internal/model"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
)

var (
	mockRefreshToken = "example_refresh_token"
	mockUsername     = "test"
	mockExpiresAt    = int64(2280000)
)

// TestLoadAndDelete tests the LoadAndDelete method
func TestLoadAndDelete(t *testing.T) {
	storage := &sync.Map{}
	session := &model.Session{
		RefreshToken: mockRefreshToken,
		Username:     mockUsername,
		ExpiresAt:    mockExpiresAt,
	}

	t.Log("Initialize the RefreshSession with the mock storage")
	refreshSession := NewRefreshSessionStorage(storage)

	t.Log("Save the session to the storage")
	refreshSession.SaveSession(session)

	t.Log("Test loading and deleting the session")
	loadedSession, loaded := refreshSession.LoadAndDelete(session.Username)
	assert.True(t, loaded, "Unexpected error")
	assert.Equal(t, session, loadedSession, "Loaded session mismatch")

	t.Log("Verify that the session is deleted from the storage")
	_, loaded = storage.Load(mockRefreshToken)
	assert.False(t, loaded, "Session was not deleted from storage")
}

// TestSaveSession tests the SaveSession method
func TestSaveSession(t *testing.T) {
	storage := &sync.Map{}
	session := &model.Session{
		RefreshToken: mockRefreshToken,
		Username:     mockUsername,
		ExpiresAt:    mockExpiresAt,
	}

	t.Log("Initialize the RefreshSession with the mock storage")
	refreshSession := NewRefreshSessionStorage(storage)

	t.Log("Save the session to the storage")
	refreshSession.SaveSession(session)

	t.Log(" Verify that the session is stored in the storage")
	storedSession, loaded := storage.Load(mockRefreshToken)
	assert.True(t, loaded, "Session was not stored in the storage")
	assert.Equal(t, session, storedSession, "Stored session mismatch")
}

// TestDelete tests the Delete method
func TestDelete(t *testing.T) {
	storage := &sync.Map{}
	session := &model.Session{
		RefreshToken: mockRefreshToken,
		Username:     mockUsername,
		ExpiresAt:    mockExpiresAt,
	}

	t.Log("Initialize the RefreshSession with the mock storage")
	refreshSession := NewRefreshSessionStorage(storage)

	t.Log(" Save the session to the storage")
	refreshSession.SaveSession(session)

	t.Log("Delete the session")
	refreshSession.Delete(mockRefreshToken)

	t.Log("Verify that the session is deleted from the storage")
	_, loaded := storage.Load(mockRefreshToken)
	assert.False(t, loaded, "Session was not deleted from storage")
}
