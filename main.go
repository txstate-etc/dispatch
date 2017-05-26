package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"time"
	"github.com/globalsign/mgo"
	log "gopkg.in/inconshreveable/log15.v2"
	"github.com/gorilla/mux"
	jwt "github.com/dgrijalva/jwt-go"
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

	mgoInfo := &mgo.DialInfo{
		Addrs: []string{Getenv("DISPATCH_DATABASE_SERVER", "localhost")},
		Timeout: 60*time.Second,
		Database: Getenv("DISPATCH_DATABASE_NAME", "dispatch"),
		Username: Getenv("DISPATCH_DATABASE_USER", ""),
		Password: Getenv("DISPATCH_DATABASE_PASSWORD", ""),
	}
	if Getenv("DISPATCH_DATABASE_SSL", "") == "true" {
		mgoInfo.DialServer = func(addr *mgo.ServerAddr) (net.Conn, error) {
			return tls.Dial("tcp", addr.String(), &tls.Config{})
		}
	}

	if SESSION, err = mgo.DialWithInfo(mgoInfo); err != nil {
		LOG.Crit("init", "error", err.Error())
		panic("Dispatch service is terminating")
	}

	// load messages from local file
	messagejson, err := ioutil.ReadFile("/go/src/dispatch/messages.json")
	if err != nil {
		LOG.Crit("init", "err", err.Error())
		panic("Dispatch service is terminating")
	}
	messages := []interface{}{}
	if err := json.Unmarshal(messagejson, &messages); err != nil {
		LOG.Crit("messages json not parseable", "err", err.Error())
		panic("Dispatch service is terminating")
	}
	db := Getdb(SESSION)
	if err := ReloadMessages(db, messages); err != nil {
		LOG.Crit("could not insert messages into database", "err", err.Error())
		panic("Dispatch service is terminating")
	}

	APNSMANAGER = apns2.NewClientManager()
}

func main() {
	go LoopForNotificationsToSend(1*time.Second)
	r := mux.NewRouter()
	r.HandleFunc("/notifications", NotificationsList).Methods("GET")
	r.HandleFunc("/notifications/count", NotificationsCount).Methods("GET")
	r.HandleFunc("/notifications", NotificationsCreate).Methods("POST")
	r.HandleFunc("/notifications", NotificationsDelete).Methods("DELETE")
	r.HandleFunc("/notifications", NotificationsPatchAll).Methods("PATCH")
	r.HandleFunc("/notifications/{id}", NotificationsPatch).Methods("PATCH")
	//r.HandleFunc("/registrations", RegistrationsList).Methods("GET")
	r.HandleFunc("/registrations", RegistrationsCreate).Methods("POST")
	r.HandleFunc("/registrations", RegistrationsDelete).Methods("DELETE")
	r.HandleFunc("/registrations/{token}", RegistrationsGet).Methods("GET")
	r.HandleFunc("/settings/{token}", SettingsGet).Methods("GET")
	r.HandleFunc("/settings/{token}", SettingsSet).Methods("POST")
	if _, err := os.Stat("/ssl/dispatch.cert.pem"); err == nil {
		err := http.ListenAndServeTLS(":443", "/ssl/dispatch.cert.pem", "/ssl/dispatch.key.pem", r)
		LOG.Crit("could not listen, exiting", "error", err)
	} else {
		err := http.ListenAndServe(":80", r)
		LOG.Crit("could not listen, exiting", "error", err)
	}
}

func NotificationsList(rw http.ResponseWriter, req *http.Request) {
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	token := req.FormValue("token")
	var results []Notification
	var err error
	if token != "" {
		results, err = GetNotificationsForToken(db, token)
		if err != nil {
			if err == mgo.ErrNotFound {
				http.Error(rw, "that token has not been registered", http.StatusUnauthorized)
				return
			} else {
				LOG.Error("error connecting to database", "err", err)
				http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
				return
			}
		}
	} else {
		http.Error(rw, "notifications request requires a device token", http.StatusBadRequest)
		return
	}
	RespondWithJson(rw, results)
}

func NotificationsCount(rw http.ResponseWriter, req *http.Request) {
	token := req.FormValue("token")
	if token == "" {
		http.Error(rw, "notifications request requires a device token", http.StatusBadRequest)
		return
	}

	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	reg, err := GetRegistration(db, token)
	if err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "that token has not been registered", http.StatusUnauthorized)
			return
		}
	} else {
		LOG.Error("error connecting to database", "err", err)
		http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
		return
	}

	count, err := GetBadgeCountForRegistration(db, reg)
	if err != nil {
		LOG.Error("error connecting to database", "err", err)
		http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
		return
	}

	RespondWithJson(rw, map[string]int{"count":count})
}

func NotificationsCreate(rw http.ResponseWriter, req *http.Request) {
	notificationarray := make([]Notification, 0)
	JsonFromBody(req, &notificationarray)
	if len(notificationarray) == 0 {
		http.Error(rw, "body must be non-empty array of notifications in JSON", http.StatusBadRequest)
		return
	}

	// authenticate via secret key that client is authorized to send notifications
	if !ProviderAuthenticationValid(req) {
		LOG.Error("Provider did not send a valid X-Dispatch-Key header")
		http.Error(rw, "authentication required", http.StatusUnauthorized)
		return
	}

	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)
	merged := MergeNotifications(db, notificationarray)

	err := SaveNotifications(db, merged)
	if err != nil {
		LOG.Error("error writing notifications to database", "err", err)
		http.Error(rw, "error writing notifications to database", http.StatusInternalServerError)
	}
}

func NotificationsPatch(rw http.ResponseWriter, req *http.Request) {
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	id := mux.Vars(req)["id"]
	n, err := GetNotification(db, id)
	if err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "notification does not exist", http.StatusNotFound)
			return
		} else {
			LOG.Error("error connecting to database", "err", err)
			http.Error(rw, "error connecting to database", http.StatusInternalServerError)
			return
		}
	}

	token := req.FormValue("token")
	if token == "" {
		http.Error(rw, "token required to authenticate this request", http.StatusUnauthorized)
		return
	}
	reg, err := GetRegistration(db, token)
	if err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "token is not registered", http.StatusUnauthorized)
			return
		} else {
			LOG.Error("error connecting to database", "err", err)
			http.Error(rw, "error connecting to database", http.StatusInternalServerError)
			return
		}
	}

	userid, present := n.Keys["user_id"]
	if !present {
		http.Error(rw, "notification not valid", http.StatusInternalServerError)
		return
	}
	if userid != reg.UserID {
		http.Error(rw, "you do not own that notification", http.StatusForbidden)
		return
	}

	patchbody := NotificationPatch{}
	if err = JsonFromBody(req, &patchbody); err != nil {
		http.Error(rw, "could not parse body", http.StatusBadRequest)
		return
	}

	err = PatchNotification(db, id, patchbody)
	if err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "notification does not exist", http.StatusNotFound)
		} else {
			LOG.Error("error connecting to database", "err", err)
			http.Error(rw, "error connecting to database", http.StatusInternalServerError)
		}
	}
}

func NotificationsPatchAll(rw http.ResponseWriter, req *http.Request) {
	token := req.FormValue("token")
	if token == "" {
		http.Error(rw, "token required to authenticate this request", http.StatusUnauthorized)
		return
	}
	patchbody := BulkNotificationPatch{}
	if err := JsonFromBody(req, &patchbody); err != nil || len(patchbody.IDs) == 0 ||
		!(patchbody.Patch.Seen || patchbody.Patch.Read || patchbody.Patch.Cleared) {
		http.Error(rw, "could not parse body", http.StatusBadRequest)
	}

	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	reg, err := GetRegistration(db, token)
	if err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "token is not registered", http.StatusUnauthorized)
			return
		} else {
			LOG.Error("error connecting to database", "err", err)
			http.Error(rw, "error connecting to database", http.StatusInternalServerError)
			return
		}
	}

	if err = PatchNotificationsByIdEnsuringUser(db, patchbody.Patch, patchbody.IDs, reg.UserID); err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "no registration found with that token", http.StatusUnauthorized)
		} else {
			LOG.Error("error connecting to database", "err", err)
			http.Error(rw, "error connecting to database", http.StatusInternalServerError)
		}
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
	// authenticate via secret key that client is authorized to send notifications
	if !ProviderAuthenticationValid(req) {
		http.Error(rw, "authentication required", http.StatusUnauthorized)
		return
	}
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	err := DeleteNotifications(db, nf)
	if err != nil {
		LOG.Error("NotificationsDelete: database error while deleting notifications", "err", err)
		http.Error(rw, "database error while deleting notifications", http.StatusInternalServerError)
		panic(err)
	}
}

// TODO: authenticating by token in here is misguided, we should
// use the JWT method instead
func RegistrationsList(rw http.ResponseWriter, req *http.Request) {
	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	user := req.FormValue("user_id")
	if user == "" {
		http.Error(rw, "registrations request requires a user id", http.StatusBadRequest)
		return
	}

	token := req.FormValue("token")
	if token == "" {
		http.Error(rw, "token required to authenticate this request", http.StatusUnauthorized)
		return
	}

	results, err := GetRegistrationsForUser(db, user)
	if err != nil {
		LOG.Error("RegistrationsList: problem connecting to database", "err", err)
		http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
		panic(err)
	}

	foundreg := false
	for _,reg := range results {
		if reg.UserID == user {
			foundreg = true
			break
		}
	}
	if !foundreg {
		http.Error(rw, "token and user_id do not match", http.StatusForbidden)
		return
	}

	RespondWithJson(rw, results)
}

func RegistrationsGet(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	token := vars["token"]

	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	reg, err := GetRegistration(db, token)
	if err != nil {
		if err == mgo.ErrNotFound {
			rw.WriteHeader(http.StatusNotFound)
		} else {
			LOG.Error("RegistrationsGet: problem connecting to database", "err", err)
			http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
			panic(err)
		}
	}

	RespondWithJson(rw, reg)
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

	jwtpublickey, err := ioutil.ReadFile("/certs/auth/jwtservice.key.pub")
	if err == nil && len(jwtpublickey) > 0 {
		jwtrsakey, err := jwt.ParseRSAPublicKeyFromPEM(jwtpublickey)
		if err != nil {
			http.Error(rw, "problem authenticating your JWT", http.StatusInternalServerError)
		}

		jwtoken := req.FormValue("jwt")
		if len(jwtoken) == 0 {
			http.Error(rw, "A JSON Web Token is required as a URL parameter for registration", http.StatusUnauthorized)
			return
		}

		token, err := jwt.ParseWithClaims(jwtoken, &JwtClaims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return jwtrsakey, nil
		})
		if err != nil {
			LOG.Error("error parsing JWT", "err", err)
		}

		if !token.Valid {
			http.Error(rw, "JSON Web Token was not valid", http.StatusUnauthorized)
			return
		}
	}

	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	err = SaveRegistration(db, reg)
	if err != nil {
		LOG.Error("RegistrationsCreate: database error while upserting registration", "err", err)
		http.Error(rw, "database error while upserting registration", http.StatusInternalServerError)
		panic(err)
	}
}

func RegistrationsDelete(rw http.ResponseWriter, req *http.Request) {
	token := req.FormValue("token")
	if token != "" {
		s := SESSION.Copy()
		defer s.Close()
		db := Getdb(s)
		DeleteRegistration(db, Registration{Token: token})
	} else {
		http.Error(rw, "registration deletion requires a device token", http.StatusBadRequest)
		return
	}
}

func SettingsGet(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	token := vars["token"]

	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	reg, err := GetRegistration(db, token)
	if err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "registration does not exist", http.StatusNotFound)
		} else {
			LOG.Error("SettingsGet: problem connecting to database", "err", err)
			http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
			panic(err)
		}
	}

	RespondWithJson(rw, reg.Settings)
}

func SettingsSet(rw http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	token := vars["token"]

	settings := Settings{}
	err := JsonFromBody(req, &settings)
	if err != nil {
		http.Error(rw, "could not parse JSON from post body", http.StatusBadRequest)
		return
	}

	s := SESSION.Copy()
	defer s.Close()
	db := Getdb(s)

	err = SaveSettings(db, token, settings)
	if err != nil {
		if err == mgo.ErrNotFound {
			http.Error(rw, "token does not exist; must register first, then update settings", http.StatusNotFound)
			return
		} else {
			LOG.Error("SettingsSet: problem connecting to database", "err", err)
			http.Error(rw, "problem connecting to database", http.StatusInternalServerError)
			panic(err)
		}
	}
}
