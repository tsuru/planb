package main

import (
	. "gopkg.in/check.v1"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
)

type LogSuite struct{}

var _ = Suite(&LogSuite{})

func (s *LogSuite) TestNewFileLogger(c *C) {
	fileName := "my-access.log"
	var err error
	_, err = NewFileLogger(fileName)
	c.Assert(err, Equals, nil)
	_, err = os.Stat(fileName)
	c.Assert(err, Equals, nil)
}

func (s *LogSuite) TestNewSyslogLogger(c *C) {
	_, err := NewSyslogLogger()
	c.Assert(err, Equals, nil)
	router := Router{}
	router.logger, err = NewSyslogLogger()
	c.Assert(err, Equals, nil)
	err = router.Init()
	c.Assert(err, Equals, nil)
	request, err := http.NewRequest("GET", "", nil)
	rsp := router.RoundTripWithData(request, &requestData{})
	c.Assert(rsp.StatusCode, Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, Equals, nil)
	c.Assert(data, DeepEquals, noRouteResponseBody.value)
	logdata := captureFileContent("/var/log/syslog")
	c.Assert(strings.Contains(logdata, "GET  HTTP/1.1\" 400 13"), Equals, true)
}

func (s *LogSuite) TestNewStdoutLogger(c *C) {
	var err error
	router := Router{}
	router.logger, err = NewStdoutLogger()
	c.Assert(err, Equals, nil)
	err = router.Init()
	c.Assert(err, Equals, nil)
	request, err := http.NewRequest("GET", "", nil)
	rsp := router.RoundTripWithData(request, &requestData{})
	c.Assert(rsp.StatusCode, Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, Equals, nil)
	c.Assert(data, DeepEquals, noRouteResponseBody.value)
}

func captureFileContent(fname string) string {
	content, err := ioutil.ReadFile(fname)
	if err != nil {
		panic(err)
	}
	return string(content)
}
