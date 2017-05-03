package main
import (
	"time"
	"fmt"
	"github.com/globalsign/mgo/bson"
)

type JsonTime time.Time

func (self JsonTime) MarshalJSON() ([]byte, error) {
	return []byte(self.String()), nil
}

func (self *JsonTime) UnmarshalJSON(b []byte) (err error) {
	s := string(b)
	s = s[1:len(s)-1]
	formats := [...]string{
		time.RFC3339Nano, time.RFC3339, time.RFC1123,
		"2006-01-02 15:04:05-0700",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02T15:04:05-0700",
		"20060102150405MST" }
	var t time.Time
	for _,format := range formats {
		t, err = time.Parse(format, s)
		if err == nil { break }
	}
	*self = JsonTime(t)
	return err
}

func (self JsonTime) GetBSON() (interface{}, error) {
	t := time.Time(self)
	if t.IsZero() {
		return nil, nil
	}
	return t, nil
}

func (self *JsonTime) SetBSON(raw bson.Raw) error {
	var t time.Time
	if err := raw.Unmarshal(&t); err != nil {
		return err
	}
	*self = JsonTime(t)
	return nil
}

func (self JsonTime) String() string {
	return fmt.Sprintf("\"%s\"", time.Time(self).Format(time.RFC3339))
}

func (self JsonTime) Time() time.Time {
	return time.Time(self)
}
