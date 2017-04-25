package main
import (
	"time"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
)

func Getdb(s *mgo.Session) *mgo.Database {
	return s.DB(Getenv("DISPATCH_DATABASE_NAME", "dispatch"))
}

func GetAllAppFilters(db *mgo.Database) ([]AppFilter, error) {
	results := make([]AppFilter, 0)

	// TEMPORARY: hack in our configuration
	results = append(results, AppFilter{AppID: "edu.txstate.mobile.tracs", Whitelist: []NotificationFilter{NotificationFilter{Keys: map[string]string{"provider_id":"tracs"}}}})
	//db.C("appfilters").Find().All(&results)

	return results, nil
}

// TEMPORARY: hacked to have our configuration hard-coded
func GetAppFilter(db *mgo.Database, appid string) (AppFilter, error) {
	filters, err := GetAllAppFilters(db)
	if err != nil {
		return AppFilter{}, err
	}
	for _,filter := range filters {
		if filter.AppID == appid {
			return filter, nil
		}
	}
	return AppFilter{}, mgo.ErrNotFound
}

func GetNotification(db *mgo.Database, nid string) (Notification, error) {
	result := Notification{}
	err := db.C("notifications").Find(bson.M{"_id": nid}).One(&result)
	return result, err
}

func GetNotificationDupe(db *mgo.Database, n Notification) (Notification, error) {
	result := Notification{}
	c := db.C("notifications")
	c.EnsureIndexKey(MapKeys(n.Keys)...)
	err := c.Find(n.Keys).Sort("-notify_after").One(&result)
	return result, err
}

func GetNotificationsUnsent(db *mgo.Database) ([]Notification, error) {
	results := make([]Notification, 0)
	c := db.C("notifications")
	idx := mgo.Index{
		Key: []string{"notify_after"},
		PartialFilter: bson.M{"sent":false},
	}
	c.EnsureIndex(idx)
	err := c.Find(bson.M{"sent": false, "notify_after": bson.M{"$lt": time.Now()}}).All(&results)
	return results, err
}

func GetNotificationsForUser(db *mgo.Database, user string) ([]Notification, error) {
	results := make([]Notification, 0)
	c := db.C("notifications")
	c.EnsureIndexKey("keys.user_id")
	err := c.Find(bson.M{"keys.user_id": user}).Sort("-notify_after").All(&results)
	return NotificationsRemoveDupes(results), err
}

func GetNotificationsForToken(db *mgo.Database, token string) ([]Notification, error) {
	results := []Notification{}
	reg, err := GetRegistration(db, token)
	if err != nil {
		return results, err
	}
	notis, err := GetNotificationsForUser(db, reg.UserID)
	if err != nil {
		return results, err
	}
	appfilter, err := GetAppFilter(db, reg.AppID)
	if err != nil {
		return results, err
	}
	ret := FilterNotificationsForRegistration(notis, appfilter, reg)
	ret = NotificationsRemoveDupes(ret)
	return ret, nil
}

func GetRegistration(db *mgo.Database, token string) (Registration, error) {
	result := Registration{}
	db.C("registrations").EnsureIndexKey("token")
	err := db.C("registrations").Find(bson.M{"token":token}).One(&result)
	return result, err
}

func GetRegistrationsForUser(db *mgo.Database, user string) ([]Registration, error) {
	results := make([]Registration, 0)
	db.C("registrations").EnsureIndexKey("user_id")
	err := db.C("registrations").Find(bson.M{"user_id": user}).All(&results)
	return results, err
}

func GetRegistrationsForUsers(db *mgo.Database, userids []string) (map[string][]Registration, error) {
	ret := make(map[string][]Registration)
	results := make([]Registration, 0)
	db.C("registrations").EnsureIndexKey("user_id")
	err := db.C("registrations").Find(bson.M{"user_id":bson.M{"$in":userids}}).All(&results)
	if err != nil {
		return ret, err
	}
	for _,reg := range results {
		ret[reg.UserID] = append(ret[reg.UserID], reg)
	}
	return ret, nil
}

func PatchNotification(db *mgo.Database, id string, newdata interface{}) error {
	return db.C("notifications").UpdateId(id, newdata)
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

func SaveNotifications(db *mgo.Database, notificationarray []Notification) error {
	b := db.C("notifications").Bulk()
	for _,n := range notificationarray {
		if n.ID.Valid() {
			b.Upsert(bson.M{"_id": n.ID}, n)
		} else {
			b.Insert(n)
		}
	}
	_, err := b.Run()
	return err
}

func MarkNotificationSent(db *mgo.Database, n Notification) {
	db.C("notifications").Update(bson.M{"_id":n.ID}, bson.M{"sent":true, "errors":n.Errors})
}

func SaveRegistration(db *mgo.Database, reg Registration) error {
	_,err := db.C("registrations").Upsert(bson.M{"token":reg.Token}, reg)
	return err
}

func DeleteRegistrationWithNewSession(reg Registration) error {
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)
	return DeleteRegistration(db, reg)
}

func DeleteRegistration(db *mgo.Database, reg Registration) error {
	err := db.C("registrations").Remove(bson.M{"token":reg.Token})
	return err
}
