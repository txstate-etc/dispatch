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
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05-0700", s)
	}
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05-07:00", s)
	}
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05-0700", s)
	}
	if err != nil {
		t, err = time.Parse("20060102150405MST", s)
	}
	self.Time = t
	return err
}

func (self *JsonTime) MarshalJSON() ([]byte, error) {
	s := fmt.Sprintf("\"%s\"", self.Time.Format("2006-01-02 15:04:05-0700"))
	return []byte(s), nil
}
