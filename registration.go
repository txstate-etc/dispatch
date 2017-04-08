package main

type Registration struct {
	Platform PlatformType `json:"platform"`
	AppID string `bson:"app_id" json:"app_id"`
	Token string `json:"token"`
	UserID string `bson:"user_id" json:"user_id"`
}

type PlatformType string
const (
	Apple PlatformType = "ios"
	Android PlatformType = "android"
)
