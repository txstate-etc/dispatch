package main

import (
	"crypto/sha1"
	"encoding/base64"
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
	fcm "github.com/txstate-etc/go-fcm"
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

func GenerateHash(content string) string {
	hasher := sha1.New()
	hasher.Write([]byte(content))
	return base64.URLEncoding.EncodeToString(hasher.Sum(nil))
}

func MapKeys(mymap interface{}) []string {
	v := reflect.ValueOf(mymap)
	if v.Kind() == reflect.Map {
		rkeys := v.MapKeys()
		ret := make([]string, len(rkeys))
		for _, kv := range rkeys {
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
	if err := MarkNotificationDupes(db, n); err != nil {
		LOG.Crit("lost a notification because database was down")
		return Notification{}, true
	}

	result, err := GetNotificationDupe(db, n)
	if err != nil && err != mgo.ErrNotFound {
		LOG.Crit("lost a notification because database was down")
		return Notification{}, true
	}

	killnotification := false
	if err == nil { // found a duplicate
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

func NotificationHashKey(n Notification) (string, error) {
	// json.Marshal encodes map keys in alphabetical order so we
	// can be certain this hash key will always be reproducible
	hashkeybytes, err := json.Marshal(n.Keys)
	return string(hashkeybytes), err
}

func NotificationsRemoveDupes(notificationarray []Notification) []Notification {
	rethash := make(map[string]Notification)
	hash := make(map[string]time.Time)
	for _, n := range notificationarray {
		hashkey, err := NotificationHashKey(n)
		if err == nil {
			existingnotify, found := hash[hashkey]
			if !found || existingnotify.Before(n.NotifyAfter.Time()) {
				hash[hashkey] = n.NotifyAfter.Time()
				rethash[hashkey] = n
			}
		}
	}
	ret := make([]Notification, 0, len(rethash))
	for _, n := range notificationarray {
		hashkey, err := NotificationHashKey(n)
		if err == nil {
			winner, ok := rethash[hashkey]
			if ok && winner.ID == n.ID {
				ret = append(ret, n)
			}
		}
	}
	return ret
}

func NotificationsRemoveUnseen(notificationarray []Notification) []Notification {
	ret := []Notification{}
	for _,n := range notificationarray {
		if !n.Seen {
			ret = append(ret, n)
		}
	}
	return ret
}

func MergeNotifications(db *mgo.Database, notificationarray []Notification) []Notification {
	ret := []Notification{}
	for _, n := range notificationarray {
		m, kill := MergeNotification(db, n)
		if !kill {
			ret = append(ret, m)
		}
	}
	return ret
}

func NotificationFilterMatches(filter NotificationFilter, n Notification) bool {
	for key, val := range filter.Keys {
		if val != n.Keys[key] {
			return false
		}
	}
	for key, val := range filter.OtherKeys {
		if val != n.OtherKeys[key] {
			return false
		}
	}
	return true
}

func AppIsInterestedInNotification(appfilter AppFilter, n Notification) bool {
	for _, filter := range appfilter.Whitelist {
		if NotificationFilterMatches(filter, n) {
			return true
		}
	}
	return false
}

func RegistrationIsInterestedInNotification(reg Registration, n Notification) bool {
	if reg.Settings.GlobalDisable {
		return false
	}
	blacklisted := false
	for _, filter := range reg.Settings.Blacklist {
		if NotificationFilterMatches(filter, n) {
			blacklisted = true
		}
	}
	return !blacklisted
}

func GetAppsInterestedInNotification(appfilters []AppFilter, n Notification) map[string]bool {
	ret := make(map[string]bool)
	for _, appfilter := range appfilters {
		if AppIsInterestedInNotification(appfilter, n) {
			ret[appfilter.AppID] = true
		}
	}
	return ret
}

func FilterNotificationsForRegistration(notifications []Notification, appfilter AppFilter, reg Registration) []Notification {
	ret := []Notification{}
	for _, n := range notifications {
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
	for _, reg := range registrations {
		if apphash[reg.AppID] { // application is interested
			if RegistrationIsInterestedInNotification(reg, n) {
				ret = append(ret, reg)
			}
		}
	}
	return ret
}

func FindMessageForNotification(messages []NotificationMessage, n Notification) NotificationMessage {
	for _, message := range messages {
		if NotificationFilterMatches(message.Filter, n) {
			return message
		}
	}
	return NotificationMessage{}
}

// function for sending a whole array of notifications, bundles up database calls to
// avoid n+1 problems
func SendNotificationArray(db *mgo.Database, notificationarray []Notification) error {
	if len(notificationarray) == 0 {
		return nil
	}
	userids := make([]string, len(notificationarray))
	for _, n := range notificationarray {
		userids = append(userids, n.Keys["user_id"])
	}
	registrations, err := GetRegistrationsForUsers(db, userids)
	if err != nil {
		return err
	}
	flatregs := []Registration{}
	for _, regs := range registrations {
		for _, r := range regs {
			flatregs = append(flatregs, r)
		}
	}
	appfilters, err := GetAllAppFilters(db)
	if err != nil {
		return err
	}
	badgecounts, err := GetBadgeCountsForRegistrations(db, flatregs)
	if err != nil {
		return err
	}
	var messages []NotificationMessage
	provider, present := notificationarray[0].Keys["provider_id"]
	if present {
		messages, err = GetAllMessagesForProvider(db, provider)
		if err != nil {
			return err
		}
	} else {
		messages = []NotificationMessage{}
	}

	for _, n := range notificationarray {
		regsforuser := registrations[n.Keys["user_id"]]
		wantstobenotified := FilterRegistrationsForNotification(regsforuser, appfilters, n)
		if !n.Sent && n.NotifyAfter.Time().Before(time.Now()) {
			message := FindMessageForNotification(messages, n)
			SendNotification(wantstobenotified, n, message, badgecounts)
			MarkNotificationSent(db, n)
		}
	}
	return nil
}

// send a single notification to all registered apps, no more database calls at this point
func SendNotification(registrations []Registration, n Notification, message NotificationMessage, badgecounts map[string]int) {
	for _, reg := range registrations {
		var err error
		if reg.Platform == Android {
			err = SendAndroidNotification(reg, n, message, badgecounts[reg.Token])
		}
		if reg.Platform == Apple {
			err = SendAppleNotification(reg, n, message, badgecounts[reg.Token])
		}
		if err != nil {
			n.Errors = true
		}
	}
}

func SendAppleNotification(reg Registration, n Notification, message NotificationMessage, badge int) error {
	cert, err := certificate.FromPemFile("/certs/ios/"+reg.AppID+".pem", "")
	if err != nil {
		LOG.Crit("Certificate Error", "error", err, "registration", reg)
		return err
	}
	notification := &apns2.Notification{}
	notification.DeviceToken = reg.Token
	notification.Topic = reg.AppID
	msg := message.Message
	if n.IsUpdate {
		msg = message.UpdateMessage
	}
	notification.Payload = payload.NewPayload().Alert(msg).Badge(badge).Sound("default")
	notification.CollapseID = GenerateHash(msg)

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

func SendAndroidNotification(reg Registration, n Notification, message NotificationMessage, badge int) error {
	apiKey := os.Getenv("DISPATCH_FCM_SECRET")
	client := fcm.NewFcmClient(apiKey)

	var msg string
	if n.IsUpdate {
		msg = message.UpdateMessage
	} else {
		msg = message.Message
	}

	notification := &fcm.NotificationPayload{
		Body: msg,
	}

	data := map[string]string{
		"shouldLoadNotificationsView": "true",
	}

	client.NewFcmMsgTo(reg.Token, data)
	client.SetNotificationPayload(notification)
	status, err := client.Send()
	if err != nil {
		LOG.Crit("Failed to push notification to Google", err, "registration", reg, "notification", n)
		return err
	}

	if status.Fail > 0 {
		DeleteRegistrationWithNewSession(reg)
	}

	if status.Success > 0 {
		LOG.Info("successfully pushed to Google", "n", n, "statusCode", status.StatusCode, "messageID", status.MsgId)
	}
	status.PrintResults()
	return nil
}

func ProviderAuthenticationValid(req *http.Request) bool {
	// authenticate via secret key that client is authorized to send notifications
	keyarray, present := req.Header["X-Dispatch-Key"]
	secret := Getenv("DISPATCH_SECRET", "")
	return len(secret) == 0 || (present && len(keyarray) > 0 && keyarray[0] == secret)
}
