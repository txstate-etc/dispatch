package main

type AppFilter struct {
	AppID string `json:"app_id"`
	Keys map[string]string `json:"keys"`
	OtherKeys map[string]string `json:"other_keys"`
}
