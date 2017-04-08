package main
import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

func Getdb(s *mgo.Session) *mgo.Database {
	return s.DB(Getenv("DISPATCH_DATABASE_NAME", "dispatch"))
}

func GetAllAppFilters(db *mgo.Database) []AppFilter {
	results := make([]AppFilter, 0)

	// TEMPORARY: hack in our configuration
	results = append(results, AppFilter{AppID: "edu.txstate.mobile.tracs", Keys: map[string]string{"provider_id":"tracs"}})
	//db.C("appfilters").Find().All(&results)

	return results
}

func GetNotificationsForUser(db *mgo.Database, user string) ([]Notification, error) {
	results := make([]Notification, 0)
	err := db.C("notifications").Find(bson.M{"keys.user_id": user}).Sort("-notifyafter").All(&results)
	return results, err
}

func GetRegistrationsForUser(db *mgo.Database, user string) ([]Registration, error) {
	results := make([]Registration, 0)
	err := db.C("registrations").Find(bson.M{"user_id": user}).All(&results)
	return results, err
}

func GetRegistrationsForUsers(db *mgo.Database, userids []string) map[string][]Registration {
	ret := make(map[string][]Registration)
	results := make([]Registration, 0)
	db.C("registrations").Find(bson.M{"user_id":bson.M{"$in":userids}}).All(&results)
	for _,reg := range results {
		ret[reg.UserID] = append(ret[reg.UserID], reg)
	}
	return ret
}

func DeleteNotifications(db *mgo.Database, nf NotificationFilter) error {
	filters := bson.M{}
	for key,val := range nf.Keys {
		filters["keys."+key] = val
	}
	for key,val := range nf.OtherKeys {
		filters["otherkeys."+key] = val
	}

	_, err := db.C("notifications").RemoveAll(filters)
	return err
}

func MarkNotificationSent(db *mgo.Database, n Notification) {
	db.C("notifications").Update(bson.M{"_id":n.ID}, bson.M{"sent":true, "errors":n.Errors})
}

func SaveRegistration(db *mgo.Database, reg Registration) error {
	_,err := db.C("registrations").Upsert(bson.M{"token":reg.Token}, reg)
	return err
}
