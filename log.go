// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	TIME_HIPACHE_MODE = "02/Jan/2006:15:04:05 -0700"
)

type Logger struct {
	logChan    chan *logEntry
	done       chan bool
	writer     io.WriteCloser
	nextNotify <-chan time.Time
}

type logEntry struct {
	now             time.Time
	req             *http.Request
	rsp             *http.Response
	backendDuration time.Duration
	totalDuration   time.Duration
	backendKey      string
}

func NewFileLogger(path string) (*Logger, error) {
	if path == "syslog" {
		return NewSyslogLogger()
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return nil, err
	}
	return NewWriterLogger(file), nil
}

func NewSyslogLogger() (*Logger, error) {
	writer, err := syslog.New(syslog.LOG_INFO|syslog.LOG_LOCAL0, "hipache")
	if err != nil {
		return nil, err
	}
	return NewWriterLogger(writer), nil
}

func NewWriterLogger(writer io.WriteCloser) *Logger {
	l := Logger{
		logChan:    make(chan *logEntry, 10000),
		done:       make(chan bool),
		writer:     writer,
		nextNotify: time.After(0),
	}
	go l.logWriter()
	return &l
}

func (l *Logger) MessageRaw(entry *logEntry) {
	select {
	case l.logChan <- entry:
	default:
		select {
		case <-l.nextNotify:
			log.Print("Dropping log messages to due to full channel buffer.")
			l.nextNotify = time.After(time.Minute)
		default:
		}
	}
}

func (l *Logger) Stop() {
	close(l.logChan)
	<-l.done
}

func (l *Logger) logWriter() {
	defer close(l.done)
	defer l.writer.Close()
	for el := range l.logChan {
		nowFormatted := el.now.Format(TIME_HIPACHE_MODE)
		remoteAddr := el.req.RemoteAddr
		ip, _, _ := net.SplitHostPort(remoteAddr)
		if ip == "" {
			ip = remoteAddr
		}
		if !strings.HasPrefix(ip, "::") {
			ip = "::ffff:" + ip
		}
		fmt.Fprintf(l.writer,
			"%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\" \"%s\" %0.3f %0.3f\n",
			ip,
			nowFormatted,
			el.req.Method,
			el.req.URL.Path,
			el.req.Proto,
			el.rsp.StatusCode,
			el.rsp.ContentLength,
			el.req.Referer(),
			el.req.UserAgent(),
			el.backendKey,
			float64(el.totalDuration)/float64(time.Second),
			float64(el.backendDuration)/float64(time.Second),
		)
	}
}

func logError(err error) {
	log.Print("ERROR: ", err.Error())
}
