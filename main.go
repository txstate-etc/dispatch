// dispatch push notifications at requested times
// docs:
//   https://godoc.org/gopkg.in/inconshreveable/log15.v2
//   http://www.gorillatoolkit.org/pkg/
package main

import (
	"errors"
	"fmt"
	"github.com/boltdb/bolt"
	log "gopkg.in/inconshreveable/log15.v2"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	//"github.com/gorilla/mux"
	//apn "github.com/sideshow/apns2"
	//gcm "https://github.com/kikinteractive/go-gcm"
)

type key int

// context keys
const (
	requestDBKey key = iota
	requestLogKey
	requestDeviceIDKey
	requestUserIDKey
)

// Temporary use of boltdb as key/value store
var STORE string

// Temporary use of global log and db
// TODO: refactor to move log and storage into context for http handlers to allow mocking out for testing.
var LOG log.Logger
var DB *bolt.DB

func init() {
	LOG = log.New("app", "dispatch")
	LOG.SetHandler(
		log.LvlFilterHandler(
			log.LvlDebug,
			log.StreamHandler(os.Stdout, log.JsonFormat())))
	os.Setenv("DISPATCH_STORE", STORE)
	if STORE == "" {
		STORE = "dispatch.bolt"
	}
	if !strings.HasPrefix(STORE, "/") {
		pwd, _ := os.Getwd()
		STORE = pwd + "/" + STORE
	}
	LOG.Info("Key/Value Store file: " + STORE)
	var err error
	DB, err = bolt.Open(STORE, 0600, nil)
	if err != nil {
		LOG.Crit(err.Error())
		panic("Dispatch service is terminating")
	}
	err = DB.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte("test"))
		return err
	})
	if err != nil {
		LOG.Crit(err.Error())
		panic("Dispatch service is terminating")
	}
}

func main() {
	r := http.NewServeMux()
	r.HandleFunc("/", TestHandler)
	LOG.Crit(http.ListenAndServe(":8000", r).Error())
}

func TestHandler(rw http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		TestGETHandler(rw, req)
	case "POST":
		TestPOSTHandler(rw, req)
	case "DELETE":
		TestDELETEHandler(rw, req)
	default:
		http.Error(rw, "Invalid request method.", 405)
		LOG.Error("TestHandler", "Invalid request method")
	}
	return
}

func TestPOSTHandler(rw http.ResponseWriter, req *http.Request) {
	k := req.URL.Path
	v, err := ioutil.ReadAll(req.Body)
	if err != nil {
		LOG.Error("TestPostHandler", err)
		return
	}
	err = DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("test"))
		return b.Put([]byte(k), v)
	})
	if err != nil {
		LOG.Error("TestPOSTHandler", err)
	} else {
		LOG.Info("TestPOSTHandler", "Successfully created or updated key: "+k)
	}
	return
}

func TestDELETEHandler(rw http.ResponseWriter, req *http.Request) {
	k := req.URL.Path
	err := DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("test"))
		return b.Delete([]byte(k))
	})
	if err != nil {
		LOG.Error("TestDELETEHandler", err)
	} else {
		LOG.Info("TestDELETEHandler", "Successfully deleted key: "+k)
	}
	return
}

func TestGETHandler(rw http.ResponseWriter, req *http.Request) {
	k := req.URL.Path
	// WARN: with boltdb if we want to use the value of v outside
	// the closure then we need to copy it
	err := DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("test"))
		v := b.Get([]byte(k))
		if v == nil {
			http.NotFound(rw, req)
			return errors.New("Entry for " + k + "was NOT found")
		} else {
			fmt.Fprintf(rw, "Value: %s", v)
		}
		return nil
	})
	if err != nil {
		LOG.Error("TestGETHandler", err)
	} else {
		LOG.Info("TestGETHandler", "Entry for "+k+" was found")
	}
	return
}
