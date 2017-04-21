package main
import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"reflect"
	"time"
	"github.com/globalsign/mgo"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
	//gcm "https://github.com/kikinteractive/go-gcm"
)

func LoopForNotificationsToSend(seconds time.Duration) {
	s := SESSION.Copy()
	defer s.Close()
	for {
		s.Refresh()
		db := Getdb(s)
		notificationarray, err := GetNotificationsUnsent(db)
		if err != nil {
			LOG.Crit("could not retrieve unsent notifications from database", "err", err)
		} else {
			err = SendNotificationArray(db, notificationarray)
			if err != nil {
				LOG.Crit("problem sending notification array", "err", err)
			}
		}

		time.Sleep(seconds)
	}
}

func Getenv(key string, def string) string {
	ret := os.Getenv(key)
	if len(ret) == 0 {
		return def
	}
	return ret
}

func MapKeys(mymap interface{}) []string {
	v := reflect.ValueOf(mymap)
	if v.Kind() == reflect.Map {
		rkeys := v.MapKeys()
		ret := make([]string, len(rkeys))
		for _,kv := range rkeys {
			ret = append(ret, kv.String())
		}
		return ret
	}
	return []string{}
}

func RespondWithJson(rw http.ResponseWriter, p interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(p)
}

func JsonFromBody(req *http.Request, ret interface{}) error {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &ret)
	if err != nil {
		return err
	}
	return nil
}

func MergeNotification(db *mgo.Database, n Notification) (Notification, bool) {
	result, err := GetNotificationDupe(db, n)
	if err != nil {
		LOG.Crit("lost a notification because database was down")
		return Notification{}, true
	}

	killnotification := false
	if result.ID != "" { // found a duplicate
		if result.Sent { // the older one has already gone out
			if result.ContentHash == n.ContentHash { // content has not changed
				killnotification = true // no new notification
			} else { // content has changed
				if n.SendUpdates { // notification source wants update messages to go out
					n.IsUpdate = true // send it but as an update
				} else { // notification source does not want update messages to go out
					killnotification = true // squelch the notification
				}
			}
		} else { // the older one has not gone out
			n.ID = result.ID // update the older notification with new data
		}
	}
	return n, killnotification
}

func MergeNotifications(db *mgo.Database, notificationarray []Notification) []Notification {
	ret := []Notification{}
	for _,n := range notificationarray {
		m,kill := MergeNotification(db, n)
		if !kill {
			ret = append(ret, m)
		}
	}
	return ret
}

func NotificationFilterMatches(filter NotificationFilter, n Notification) bool {
	for key,val := range filter.Keys {
		if val != n.Keys[key] {
			return false
		}
	}
	for key,val := range filter.OtherKeys {
		if val != n.OtherKeys[key] {
			return false
		}
	}
	return true
}

func AppIsInterestedInNotification(appfilter AppFilter, n Notification) bool {
	for _,filter := range appfilter.Whitelist {
		if NotificationFilterMatches(filter, n) {
			return true
		}
	}
	return false
}

func RegistrationIsInterestedInNotification(reg Registration, n Notification) bool {
	blacklisted := false
	for _,filter := range reg.Blacklist {
		if NotificationFilterMatches(filter, n) {
			blacklisted = true
		}
	}
	return !blacklisted
}

func GetAppsInterestedInNotification(appfilters []AppFilter, n Notification) map[string]bool {
	ret := make(map[string]bool)
	for _,appfilter := range appfilters {
		if AppIsInterestedInNotification(appfilter, n) {
			ret[appfilter.AppID] = true
		}
	}
	return ret
}

func FilterNotificationsForRegistration(notifications []Notification, appfilter AppFilter, reg Registration) []Notification {
	ret := []Notification{}
	for _,n := range notifications {
		if AppIsInterestedInNotification(appfilter, n) {
			if RegistrationIsInterestedInNotification(reg, n) {
				ret = append(ret, n)
			}
		}
	}
	return ret
}

func FilterRegistrationsForNotification(registrations []Registration, appfilters []AppFilter, n Notification) []Registration {
	apphash := GetAppsInterestedInNotification(appfilters, n)
	ret := make([]Registration, 0)
	for _,reg := range registrations {
		if apphash[reg.AppID] { // application is interested
			if RegistrationIsInterestedInNotification(reg, n) {
				ret = append(ret, reg)
			}
		}
	}
	return ret
}

// function for sending a whole array of notifications, bundles up database calls to
// avoid n+1 problems
func SendNotificationArray(db *mgo.Database, notificationarray []Notification) error {
	userids := make([]string,len(notificationarray))
	for _,n := range notificationarray {
		userids = append(userids, n.Keys["user_id"])
	}
	registrations, err := GetRegistrationsForUsers(db, userids)
	if err != nil {
		return err
	}
	appfilters, err := GetAllAppFilters(db)
	if err != nil {
		return err
	}

	for _,n := range notificationarray {
		regsforuser := registrations[n.Keys["user_id"]]
		wantstobenotified := FilterRegistrationsForNotification(regsforuser, appfilters, n)
		if !n.Sent && n.NotifyAfter.Time.Before(time.Now()) {
			SendNotification(wantstobenotified, n, 3)
			MarkNotificationSent(db, n)
		}
	}
	return nil
}

// send a single notification to all registered apps, no more database calls at this point
func SendNotification(registrations []Registration, n Notification, badge int) {
	for _,reg := range registrations {
		var err error
		if reg.Platform == Android { err = SendAndroidNotification(reg, n, badge) }
		if reg.Platform == Apple { err = SendAppleNotification(reg, n, badge) }
		if err != nil {
			n.Errors = true
		}
	}
}

func SendAppleNotification(reg Registration, n Notification, badge int) error {
	cert, err := certificate.FromPemFile("/certs/ios/"+reg.AppID+".pem", "")
	if err != nil {
		LOG.Crit("Certificate Error", "error", err, "registration", reg)
		return err
	}
	notification := &apns2.Notification{}
	notification.DeviceToken = reg.Token
	notification.Topic = reg.AppID
	notification.Payload = payload.NewPayload().Alert(n.Message).Badge(badge)

	client := APNSMANAGER.Get(cert)
	if Getenv("DISPATCH_ENVIRONMENT", "development") == "production" {
		client = client.Production()
	} else {
		client = client.Development()
	}
	res, err := client.Push(notification)
	if err != nil {
		LOG.Crit("Failed to push notification to Apple", err, "registration", reg, "notification", n)
		return err
	}
	if res.StatusCode == http.StatusGone { // apple is telling us the device is no longer registered
		DeleteRegistrationWithNewSession(reg)
	}
	LOG.Info("successfully pushed to Apple", "n", n, "statusCode", res.StatusCode, "ApnsID", res.ApnsID, "Reason", res.Reason)
	return nil
}

func SendAndroidNotification(reg Registration, n Notification, badge int) error {
	return nil
}
