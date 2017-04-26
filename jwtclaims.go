package main

import (
	"errors"
	"time"
)

type JwtClaims struct {
	Expires JsonTime `json:"expires"`
	UserID string `json:"user_id"`
}

var (
	JwtInvalidUserError = errors.New("user_id not claimed")
	JwtExpiredError = errors.New("user_id not claimed")
)

func (c JwtClaims) Valid() error {
	if c.UserID == "" {
		return JwtInvalidUserError
	}
	if c.Expires.Time.Before(time.Now()) {
		return JwtExpiredError
	}
	return nil
}
