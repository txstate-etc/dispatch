package main
import (
	"time"
	"fmt"
)

type JsonTime struct {
	time.Time
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
	self.Time = t
	return err
}

func (self *JsonTime) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("\"%s\"", self.Time.Format(time.RFC3339))
	return []byte(s), nil
}
