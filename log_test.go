package main

import (
	. "gopkg.in/check.v1"
	"os"
)

type LogSuite struct{}

var _ = Suite(&LogSuite{})

func (s *LogSuite) TestNewFileLogger(c *C) {
	_, err := NewFileLogger("./my-access.log")
	c.Assert(err, Equals, nil)
	_, err = os.Stat("my-access.log")
	c.Assert(err, Equals, nil)
	err = os.Remove("./my-access.log")
}

func (s *LogSuite) TestNewSyslogLogger(c *C) {
	_, err := NewSyslogLogger()
	c.Assert(err, Equals, nil)
}

func (s *LogSuite) TestNewStdoutLogger(c *C) {
	_, err := NewStdoutLogger()
	c.Assert(err, Equals, nil)
	_, err = os.Stat("stdout")
	c.Assert(err, Equals, nil)
}
