package main
import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"time"
	"gopkg.in/mgo.v2"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/payload"
	//gcm "https://github.com/kikinteractive/go-gcm"
)

func Getenv(key string, def string) string {
	ret := os.Getenv(key)
	if len(ret) == 0 {
		return def
	}
	return ret
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

func IsInterestedInNotification(filter AppFilter, n Notification) bool {
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

func GetAppsInterestedInNotification(appfilters []AppFilter, n Notification) map[string]bool {
	ret := make(map[string]bool)
	for _,filter := range appfilters {
		if IsInterestedInNotification(filter, n) {
			ret[filter.AppID] = true
		}
	}
	return ret
}

func FilterRegistrationsForNotification(registrations []Registration, appfilters []AppFilter, n Notification) []Registration {
	apphash := GetAppsInterestedInNotification(appfilters, n)
	ret := make([]Registration, 0)
	for _,reg := range registrations {
		if apphash[reg.AppID] {
			ret = append(ret, reg)
		}
	}
	return ret
}

// function for sending a whole array of notifications, bundles up database calls to
// avoid n+1 problems
func SendNotificationArray(db *mgo.Database, notificationarray []Notification) {
	userids := make([]string,len(notificationarray))
	for _,n := range notificationarray {
		userids = append(userids, n.Keys["user_id"])
	}
	registrations := GetRegistrationsForUsers(db, userids)
	appfilters := GetAllAppFilters(db)

	for _,n := range notificationarray {
		regsforuser := registrations[n.Keys["user_id"]]
		wantstobenotified := FilterRegistrationsForNotification(regsforuser, appfilters, n)
		if !n.Sent && n.NotifyAfter.Time.Before(time.Now()) {
			SendNotification(wantstobenotified, n, 3)
			MarkNotificationSent(db, n)
		}
	}
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
	LOG.Info("successfully pushed to Apple", "n", n, "statusCode", res.StatusCode, "ApnsID", res.ApnsID, "Reason", res.Reason)
	return nil
}

func SendAndroidNotification(reg Registration, n Notification, badge int) error {
	return nil
}
