// dispatch push notifications at requested times
// docs:
//   https://godoc.org/gopkg.in/inconshreveable/log15.v2
//   http://www.gorillatoolkit.org/pkg/
package main

import (
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	log "gopkg.in/inconshreveable/log15.v2"
	"net/http"
	"os"
	"github.com/gorilla/mux"
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
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/notifications", NotificationsList).Methods("GET")
	r.HandleFunc("/notifications", NotificationsCreate).Methods("POST")
	r.HandleFunc("/notifications", NotificationsDelete).Methods("DELETE")
	r.HandleFunc("/registrations", RegistrationsList).Methods("GET")
	r.HandleFunc("/registrations", RegistrationsCreate).Methods("POST")
	r.HandleFunc("/registrations", RegistrationsDelete).Methods("DELETE")
	LOG.Crit("main", "error", http.ListenAndServe(":8000", r).Error())
}

func NotificationsList(rw http.ResponseWriter, req *http.Request) {
	s := SESSION.Copy()
	defer s.Close()
	c := Getdb(s).C("notifications")
	results := make([]Notification, 0)

	user := req.FormValue("user_id")
	if user != "" {
		c.Find(bson.M{"keys.user_id": user}).Sort("-notifyafter").All(&results)
	} else {
		http.Error(rw, "notifications request requires a user id", http.StatusBadRequest)
		return
	}
	RespondWithJson(rw, results)
}

func NotificationsCreate(rw http.ResponseWriter, req *http.Request) {
	notificationarray := make([]Notification, 0)
	JsonFromBody(req, &notificationarray)
	LOG.Info("parsed body", "notificationarray", notificationarray)
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
			http.Error(rw, "error writing notification to database", http.StatusInternalServerError)
			panic(err)
		}
		for _,n := range notificationarray {
			ConditionallySendNotification(db, n)
		}
	} else {
		http.Error(rw, "body must be non-empty array of notifications in JSON", http.StatusBadRequest)
	}
}

func NotificationsDelete(rw http.ResponseWriter, req *http.Request) {
	n := Notification{}
	JsonFromBody(req, &n)
	if len(n.Keys) == 0 && len(n.OtherKeys) == 0 {
		http.Error(rw, "body must be object with keys to use as filters", http.StatusBadRequest)
		return
	}
	if n.Keys["provider_id"] == "" {
		http.Error(rw, "keys.provider_id is required for all deletions", http.StatusBadRequest)
		return
	}

	filters := bson.M{}
	for key,val := range n.Keys {
		filters["keys."+key] = val
	}
	for key,val := range n.OtherKeys {
		filters["otherkeys."+key] = val
	}

	s := SESSION.Copy()
	defer s.Close()
	c := Getdb(s).C("notifications")
	_, err := c.RemoveAll(filters)
	if err != nil {
		http.Error(rw, "database error while deleting notifications", http.StatusInternalServerError)
		panic(err)
	}
}

func RegistrationsList(rw http.ResponseWriter, req *http.Request) {
	s := SESSION.Copy()
	defer s.Close()
	c := Getdb(s).C("registrations")
	results := make([]Registration, 0)

	user := req.FormValue("user_id")
	if user != "" {
		c.Find(bson.M{"userid": user}).All(&results)
	} else {
		http.Error(rw, "registrations request requires a user id", http.StatusBadRequest)
		return
	}
	RespondWithJson(rw, results)
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
	c := db.C("registrations")
	_,err = c.Upsert(bson.M{"token":reg.Token}, reg)
	if err != nil {
		http.Error(rw, "database error while upserting registration", http.StatusInternalServerError)
		panic(err)
	}
}

func RegistrationsDelete(rw http.ResponseWriter, req *http.Request) {

}
