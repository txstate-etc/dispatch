package main
import (
	"encoding/json"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"net/http"
	"os"
	"time"
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

func Getdb(s *mgo.Session) *mgo.Database {
	return s.DB(Getenv("DISPATCH_DATABASE_NAME", "dispatch"))
}

func RespondWithJson(rw http.ResponseWriter, p interface{}) {
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(p)
}

func JsonFromBody(req *http.Request, ret interface{}) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(body, &ret)
	if err != nil {
		panic(err)
	}
}

func getRegistrationsForUser(db *mgo.Database, uid string) *[]Registration {
	results := make([]Registration, 0)
	db.C("registrations").Find(bson.M{"user_id":uid}).All(&results)
	return &results
}

func ConditionallySendNotification(db *mgo.Database, n Notification) {
	if n.NotifyAfter.Time.Before(time.Now()) {
		SendNotification(db, n, 3)
	}
}

func SendNotification(db *mgo.Database, n Notification, badge int) {
	uid := n.Keys["user_id"]
	registrations := *getRegistrationsForUser(db, uid)
	had_errors := false
	for _,reg := range registrations {
		var err error
		if reg.Platform == Android { err = SendAndroidNotification(reg, badge, n) }
		if reg.Platform == Apple { err = SendAppleNotification(reg, badge, n) }
		if err != nil {
			had_errors = true
		}
	}
	db.C("notifications").Update(bson.M{"_id":n.ID}, bson.M{"sent":true, "errors":had_errors})
}

func SendAppleNotification(reg Registration, badge int, n Notification) error {
	cert, err := certificate.FromPemFile("/certs/"+reg.AppID+".ios.pem", "")
	if err != nil {
		LOG.Crit("Certificate Error", "error", err, "registration", reg)
		return err
	}
	notification := &apns2.Notification{}
	notification.DeviceToken = reg.Token
	notification.Topic = reg.AppID
	notification.Payload = payload.NewPayload().Alert("You have a new notification.").Badge(badge)

	client := apns2.NewClient(cert).Development()
	res, err := client.Push(notification)
	if err != nil {
		LOG.Crit("Failed to push notification to Apple", err, "registration", reg, "notification", n)
		return err
	}
	LOG.Info("successfully pushed to Apple", "statusCode", res.StatusCode, "ApnsID", res.ApnsID, "Reason", res.Reason)
	return nil
}

func SendAndroidNotification(reg Registration, badge int, n Notification) error {
	return nil
}
