package main

type AppFilter struct {
	AppID string `json:"app_id"`
	Whitelist []NotificationFilter `json:"whitelist"`
}
