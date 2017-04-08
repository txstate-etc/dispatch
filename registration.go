package main

type Registration struct {
	UserID string `json:"user_id"`
	Platform PlatformType `json:"platform"`
	Token string `json:"token"`
	AppID string `json:"app_id"`
}

type PlatformType string
const (
	Apple PlatformType = "ios"
	Android PlatformType = "android"
)
