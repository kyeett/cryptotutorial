package main

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestService() *basicService {
	return &basicService{
		keys:              map[string]string{},
		challenges:        map[string]string{},
		authentiationFunc: testAuth,
	}
}

func testAuth(s *basicService, id, resp string) error {
	if s.keys[id]+s.challenges[id] != resp {
		return errAuthenticationFailure
	}
	return nil
}

func TestNewChallengeInvalidID(t *testing.T) {
	s := newTestService()
	_, err := s.newChallenge(uuid.New().String())
	assert.Equal(t, err, errInvalidID)
}

func TestNewChallenge(t *testing.T) {
	s := newTestService()
	id := uuid.New().String()

	s.enroll(id, "some key")
	challenge, err := s.newChallenge(id)
	require.NoError(t, err)
	assert.NotNil(t, challenge)
}

func TestAuthenticationSuccess(t *testing.T) {
	s := newTestService()
	id := uuid.New().String()

	s.enroll(id, "some key")
	challenge, err := s.newChallenge(id)
	require.NoError(t, err)
	assert.NotNil(t, challenge)

	err = s.authenticate(id, "some key"+*challenge)
	require.NoError(t, err)
}
