// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"gopkg.in/check.v1"
)

type LogSuite struct{}

var _ = check.Suite(&LogSuite{})

func Test(t *testing.T) {
	check.TestingT(t)
}

type bufferCloser struct {
	bytes.Buffer
}

func (b *bufferCloser) Close() error {
	return nil
}

func (s *LogSuite) TestNewFileLogger(c *check.C) {
	file, err := ioutil.TempFile("", "loggettest")
	c.Assert(err, check.IsNil)
	file.Close()
	fileName := file.Name()
	defer os.Remove(fileName)
	logger, err := NewFileLogger(fileName)
	c.Assert(err, check.IsNil)
	_, err = os.Stat(fileName)
	c.Assert(err, check.IsNil)
	logger.MessageRaw(&LogEntry{})
	logger.Stop()
	data, err := ioutil.ReadFile(fileName)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "::ffff: - - [01/Jan/0001:00:00:00 +0000] \"  \" 0 0 \"\" \"\" \":\" \"\" 0.000 0.000\n")
}

func (s *LogSuite) TestNewSyslogLogger(c *check.C) {
	logger, err := NewSyslogLogger()
	c.Assert(err, check.IsNil)
	logger.MessageRaw(&LogEntry{})
	logger.Stop()
}

func (s *LogSuite) TestNewStdoutLogger(c *check.C) {
	logger, err := NewStdoutLogger()
	c.Assert(err, check.IsNil)
	logger.MessageRaw(&LogEntry{})
	logger.Stop()
}

func (s *LogSuite) TestNewWriterLogger(c *check.C) {
	buffer := &bufferCloser{}
	logger := NewWriterLogger(buffer)
	logger.MessageRaw(&LogEntry{})
	logger.Stop()
	c.Assert(buffer.String(), check.Equals, "::ffff: - - [01/Jan/0001:00:00:00 +0000] \"  \" 0 0 \"\" \"\" \":\" \"\" 0.000 0.000\n")
}
