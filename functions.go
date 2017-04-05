package main
import (
	"encoding/json"
	"gopkg.in/mgo.v2"
	"io/ioutil"
	"net/http"
	"os"
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

func JsonFromBody(req *http.Request) interface{} {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		panic(err)
	}
	var ret interface{}
	err = json.Unmarshal(body, &ret)
	if err != nil {
		panic(err)
	}
	return ret
}
