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

func GetAppFilter(db *mgo.Database, appid string) (AppFilter, error) {
	result, err := GetAppFilters(db, []string{appid})
	if err != nil {
		return AppFilter{}, err
	}

	ret, ok := result[appid]
	if !ok {
		return ret, mgo.ErrNotFound
	}
	return ret, nil
}

// TEMPORARY: hacked to have our configuration hard-coded
func GetAppFilters(db *mgo.Database, appids []string) (map[string]AppFilter, error) {
	ret := map[string]AppFilter{}
	filters, err := GetAllAppFilters(db)
	if err != nil {
		return ret, err
	}
	hash := map[string]bool{}
	for _,app := range appids {
		hash[app] = true
	}
	for _,filter := range filters {
		if hash[filter.AppID] {
			ret[filter.AppID] = filter
		}
	}
	return ret, nil
}

func GetNotification(db *mgo.Database, nid string) (Notification, error) {
	result := Notification{}
	err := db.C("notifications").FindId(bson.ObjectIdHex(nid)).One(&result)
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
	idx := mgo.Index{
		Key: []string{"keys.user_id", "notify_after"},
		PartialFilter: bson.M{"sent":true, "cleared":false},
	}
	c.EnsureIndex(idx)
	err := c.Find(bson.M{"keys.user_id": user, "sent":true, "cleared":false}).Sort("-notify_after").All(&results)
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

func GetNotificationsForUsers(db *mgo.Database, users []string) (map[string][]Notification, error) {
	results := []Notification{}
	c := db.C("notifications")
	idx := mgo.Index{
		Key: []string{"keys.user_id"},
		PartialFilter: bson.M{"sent":true, "cleared":false},
	}
	c.EnsureIndex(idx)
	err := c.Find(bson.M{"keys.user_id": bson.M{"$in":users}, "sent":true, "cleared":false}).All(&results)
	ret := map[string][]Notification{}
	for _,n := range results {
		ret[n.Keys["user_id"]] = append(ret[n.Keys["user_id"]], n)
	}
	return ret, err
}

func GetBadgeCountsForRegistrations(db *mgo.Database, regs []Registration) (map[string]int, error) {
	ret := map[string]int{}
	userids := []string{}
	appids := []string{}
	for _,r := range regs {
		userids = append(userids, r.UserID)
		appids = append(appids, r.AppID)
	}
	notis, err := GetNotificationsForUsers(db, userids)
	if err != nil {
		return ret, err
	}
	appfilters, err := GetAppFilters(db, appids)
	if err != nil {
		return ret, err
	}

	for _,r := range regs {
		filtered := FilterNotificationsForRegistration(notis[r.UserID], appfilters[r.AppID], r)
		filtered = NotificationsRemoveDupes(filtered)
		filtered = NotificationsRemoveUnseen(filtered)
		ret[r.Token] = len(filtered)
	}
	return ret, nil
}

func GetBadgeCountForRegistration(db *mgo.Database, reg Registration) (int, error) {
	result, err := GetBadgeCountsForRegistrations(db, []Registration{reg})
	ret := result[reg.Token]
	return ret, err
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
	return db.C("notifications").UpdateId(bson.ObjectIdHex(id), bson.M{"$set":newdata})
}

func PatchNotificationsByIdEnsuringUser(db *mgo.Database, patch interface{}, ids []bson.ObjectId, userid string) error {
	_,err := db.C("notifications").UpdateAll(bson.M{"keys.user_id":userid, "_id":bson.M{"$in":ids}}, bson.M{"$set":patch})
	return err
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
	db.C("notifications").Update(bson.M{"_id":n.ID}, bson.M{"$set":bson.M{"sent":true, "errors":n.Errors}})
}

func SaveRegistration(db *mgo.Database, reg Registration) error {
	_,err := db.C("registrations").Upsert(bson.M{"token":reg.Token}, reg)
	return err
}

func SaveSettings(db *mgo.Database, token string, settings Settings) error {
	err := db.C("registrations").Update(bson.M{"token":token}, bson.M{"$set":bson.M{"settings":settings}})
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

func ReloadMessages(db *mgo.Database, messages []interface{}) error {
	c := db.C("messages")
	if err := c.DropCollection(); err != nil && err.Error() != "ns not found" {
		return err
	}
	return c.Insert(messages...)
}

func GetAllMessagesForProvider(db *mgo.Database, provider string) ([]NotificationMessage, error) {
	results := []NotificationMessage{}
	err := db.C("messages").Find(bson.M{"filter.keys.provider_id":provider}).All(&results)
	return results, err
}
