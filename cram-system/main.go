package main

import (
	"errors"

	"github.com/google/uuid"
)

type service interface {
	enroll(id, publicKey string)
	newChallenge(id string) (*string, error)
	authenticate(id, response string) error
}

var _ service = &basicService{}

var errInvalidID = errors.New("invalid ID")
var errChallengeID = errors.New("invalid challenge")
var errAuthenticationFailure = errors.New("authentication failed")

type basicService struct {
	keys              map[string]string
	challenges        map[string]string
	authentiationFunc func(s *basicService, id, response string) error
}

func newService() *basicService {
	return &basicService{
		keys:              map[string]string{},
		challenges:        map[string]string{},
		authentiationFunc: func(s *basicService, id, resp string) error { return nil },
	}
}

func (s *basicService) enroll(id, publicKey string) {
	s.keys[id] = publicKey
}

func (s *basicService) newChallenge(id string) (*string, error) {
	if _, found := s.keys[id]; !found {
		return nil, errInvalidID
	}

	challenge := uuid.New().String()
	s.challenges[id] = challenge
	return &challenge, nil
}

func (s *basicService) authenticate(id, response string) error {
	if _, found := s.challenges[id]; !found {
		return errChallengeID
	}

	if err := s.authentiationFunc(s, id, response); err != nil {
		return errAuthenticationFailure
	}
	return nil
}
