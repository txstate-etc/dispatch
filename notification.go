package main
import (
	"gopkg.in/mgo.v2/bson"
	"time"
)

type Notification struct {
	ID bson.ObjectId `bson:"_id,omitempty" json:"id"`
	Sent bool
	Seen bool
	Read bool
	Cleared bool
	ContentHash string `json:"content_hash"`
	SendUpdates bool `json:"send_updates"`
	NotifyAfter time.Time `json:"notify_after"`
	Keys interface{}
	OtherKeys interface{} `json:"other_keys"`
}
