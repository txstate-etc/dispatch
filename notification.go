package main
import (
	"github.com/globalsign/mgo/bson"
)

type Notification struct {
	ID bson.ObjectId `bson:"_id,omitempty" json:"id"`
	Sent bool `json:"sent"`
	Seen bool `json:"seen"`
	Read bool `json:"read"`
	Cleared bool `json:"cleared"`
	IsUpdate bool `json:"is_update" bson:"is_update"`
	Errors bool `json:"errors"`
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

type NotificationMessage struct {
	Message string `json:"message"`
	UpdateMessage string `json:"update_message" bson:"update_message"`
	Filter NotificationFilter `json:"filter"`
}

type NotificationPatch struct {
	Seen bool `json:"seen"`
	Read bool `json:"read"`
	Cleared bool `json:"cleared"`
}

type BulkNotificationPatch struct {
	IDs []bson.ObjectId `json:"ids"`
	Patch NotificationPatch `json:"patches"`
}
