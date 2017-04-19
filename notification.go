package main
import (
	"gopkg.in/mgo.v2/bson"
)

type Notification struct {
	ID bson.ObjectId `bson:"_id,omitempty" json:"id"`
	Sent bool `json:"sent"`
	Seen bool `json:"seen"`
	Read bool `json:"read"`
	Cleared bool `json:"cleared"`
	Errors bool `json:"errors"`
	Message string `json:"message"`
	ContentHash string `json:"content_hash"`
	SendUpdates bool `json:"send_updates"`
	NotifyAfter JsonTime `json:"notify_after" bson:"notify_after"`
	Keys map[string]string `json:"keys"`
	OtherKeys map[string]string `json:"other_keys"`
}

type NotificationFilter struct {
	Keys map[string]string `json:"keys"`
	OtherKeys map[string]string `json:"other_keys"`
}
