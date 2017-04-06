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
	ContentHash string `json:"content_hash"`
	SendUpdates bool `json:"send_updates"`
	NotifyAfter JsonTime `json:"notify_after"`
	Keys interface{} `json:"keys"`
	OtherKeys interface{} `json:"other_keys"`
}
