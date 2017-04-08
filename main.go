// dispatch push notifications at requested times
// docs:
//   https://godoc.org/gopkg.in/inconshreveable/log15.v2
//   http://www.gorillatoolkit.org/pkg/
package main

import (
	"net/http"
	"os"
	"gopkg.in/mgo.v2"
	log "gopkg.in/inconshreveable/log15.v2"
	"github.com/gorilla/mux"
	"github.com/sideshow/apns2"
)

type key int

// context keys
const (
	requestDBKey key = iota
	requestLogKey
	requestDeviceIDKey
	requestUserIDKey
)

// Temporary use of global log and db
// TODO: refactor to move log and storage into context for http handlers to allow mocking out for testing.
var LOG log.Logger
var SESSION *mgo.Session
var APNSMANAGER *apns2.ClientManager

func init() {
	LOG = log.New("app", "dispatch")
	LOG.SetHandler(
		log.LvlFilterHandler(
			log.LvlDebug,
			log.StreamHandler(os.Stdout, log.JsonFormat())))
	var err error

	server := Getenv("DISPATCH_DATABASE_SERVER", "localhost")

	SESSION, err = mgo.Dial(server)
	if err != nil {
		LOG.Crit("init", "error", err.Error())
		panic("Dispatch service is terminating")
	}

	APNSMANAGER = apns2.NewClientManager()
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/notifications", NotificationsList).Methods("GET")
	r.HandleFunc("/notifications", NotificationsCreate).Methods("POST")
	r.HandleFunc("/notifications", NotificationsDelete).Methods("DELETE")
	r.HandleFunc("/registrations", RegistrationsList).Methods("GET")
	r.HandleFunc("/registrations", RegistrationsCreate).Methods("POST")
	r.HandleFunc("/registrations", RegistrationsDelete).Methods("DELETE")
	for {
		err := http.ListenAndServe(Getenv("DISPATCH_PORT", ":8000"), r)
		LOG.Crit("request panicked", "error", err)
	}
}

func NotificationsList(rw http.ResponseWriter, req *http.Request) {
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	user := req.FormValue("user_id")
	if user != "" {
		results, err := GetNotificationsForUser(db, user)
		if err != nil {
			http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
			panic(err)
		}
		RespondWithJson(rw, results)
	} else {
		http.Error(rw, "notifications request requires a user id", http.StatusBadRequest)
		return
	}
}

func NotificationsCreate(rw http.ResponseWriter, req *http.Request) {
	notificationarray := make([]Notification, 0)
	JsonFromBody(req, &notificationarray)
	if len(notificationarray) > 0 {
		s := SESSION.Copy()
		defer s.Close()
		db := Getdb(s)
		c := db.C("notifications")
		b := c.Bulk()

		for _,n := range notificationarray {
			b.Insert(n)
		}
		_, err := b.Run()
		if err != nil {
			http.Error(rw, "error writing notifications to database", http.StatusInternalServerError)
			panic(err)
		}

		SendNotificationArray(db, notificationarray)
	} else {
		http.Error(rw, "body must be non-empty array of notifications in JSON", http.StatusBadRequest)
	}
}

func NotificationsDelete(rw http.ResponseWriter, req *http.Request) {
	nf := NotificationFilter{}
	JsonFromBody(req, &nf)
	if len(nf.Keys) == 0 && len(nf.OtherKeys) == 0 {
		http.Error(rw, "body must be JSON object with keys to use as filters", http.StatusBadRequest)
		return
	}
	if nf.Keys["provider_id"] == "" {
		http.Error(rw, "keys.provider_id is required for all deletions", http.StatusBadRequest)
		return
	}
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	err := DeleteNotifications(db, nf)
	if err != nil {
		http.Error(rw, "database error while deleting notifications", http.StatusInternalServerError)
		panic(err)
	}
}

func RegistrationsList(rw http.ResponseWriter, req *http.Request) {
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	user := req.FormValue("user_id")
	if user != "" {
		results, err := GetRegistrationsForUser(db, user)
		if err != nil {
			http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
			panic(err)
		}
		RespondWithJson(rw, results)
	} else {
		http.Error(rw, "registrations request requires a user id", http.StatusBadRequest)
		return
	}
}

func RegistrationsCreate(rw http.ResponseWriter, req *http.Request) {
	reg := Registration{}
	err := JsonFromBody(req, &reg)
	if err != nil {
		http.Error(rw, "registration body must be JSON", http.StatusBadRequest)
		return
	}
	if len(reg.Token) == 0 || len(reg.UserID) == 0 || len(reg.Platform) == 0 || len(reg.AppID) == 0 {
		http.Error(rw, "registration requires a device token, user id, platform and app id", http.StatusBadRequest)
		return
	}
	LOG.Info("parsed registration body", "reg", reg)
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	err = SaveRegistration(db, reg)
	if err != nil {
		http.Error(rw, "database error while upserting registration", http.StatusInternalServerError)
		panic(err)
	}
}

func RegistrationsDelete(rw http.ResponseWriter, req *http.Request) {

}
