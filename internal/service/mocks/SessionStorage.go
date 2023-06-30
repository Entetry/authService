// Code generated by mockery v2.16.0. DO NOT EDIT.

package mocks

import (
	"github.com/Entetry/authService/internal/model"
	mock "github.com/stretchr/testify/mock"
)

// SessionStorage is an autogenerated mock type for the SessionStorage type
type SessionStorage struct {
	mock.Mock
}

// Delete provides a mock function with given fields: refreshToken
func (_m *SessionStorage) Delete(refreshToken string) {
	_m.Called(refreshToken)
}

// Load provides a mock function with given fields: username
func (_m *SessionStorage) Load(username string) (*model.Session, bool) {
	ret := _m.Called(username)

	var r0 *model.Session
	if rf, ok := ret.Get(0).(func(string) *model.Session); ok {
		r0 = rf(username)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Session)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// LoadAndDelete provides a mock function with given fields: refreshToken
func (_m *SessionStorage) LoadAndDelete(refreshToken string) (*model.Session, bool) {
	ret := _m.Called(refreshToken)

	var r0 *model.Session
	if rf, ok := ret.Get(0).(func(string) *model.Session); ok {
		r0 = rf(refreshToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Session)
		}
	}

	var r1 bool
	if rf, ok := ret.Get(1).(func(string) bool); ok {
		r1 = rf(refreshToken)
	} else {
		r1 = ret.Get(1).(bool)
	}

	return r0, r1
}

// SaveSession provides a mock function with given fields: session
func (_m *SessionStorage) SaveSession(session *model.Session) {
	_m.Called(session)
}

type mockConstructorTestingTNewSessionStorage interface {
	mock.TestingT
	Cleanup(func())
}

// NewSessionStorage creates a new instance of SessionStorage. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewSessionStorage(t mockConstructorTestingTNewSessionStorage) *SessionStorage {
	mock := &SessionStorage{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
