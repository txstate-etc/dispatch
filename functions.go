package main
import (
	"encoding/json"
	"gopkg.in/mgo.v2"
	"io/ioutil"
	"net/http"
	"os"
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

func SendAppleNotification(token string, topic string, badge int, n Notification) {
	cert, err := certificate.FromPemFile("/certs/edu.txstate.mobile.tracs.ios.pem", "")
	if err != nil {
		LOG.Crit("Certificate Error", "error", err)
		return
	}
	notification := &apns2.Notification{}
	notification.DeviceToken = token
	notification.Topic = topic
	notification.Payload = payload.NewPayload().Alert("You have a new notification.").Badge(badge)

	client := apns2.NewClient(cert).Development()
	res, err := client.Push(notification)
	if err != nil {
		LOG.Crit("Failed to push notification to Apple", err)
		return
	}
	LOG.Info("successfully pushed to Apple", "statusCode", res.StatusCode, "ApnsID", res.ApnsID, "Reason", res.Reason)
}
