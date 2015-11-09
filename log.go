// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	TIME_ALIGNED_NANO = "2006-01-02T15:04:05.000000000Z07:00"
)

type Logger struct {
	logChan    chan *logEntry
	done       chan bool
	writer     io.WriteCloser
	nextNotify <-chan time.Time
}

type logEntry struct {
	now      time.Time
	req      *http.Request
	rsp      *http.Response
	duration time.Duration
}

func NewFileLogger(path string) (*Logger, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return nil, err
	}
	return NewWriterLogger(file), nil
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

func (l *Logger) MessageRaw(now time.Time, req *http.Request, rsp *http.Response, duration time.Duration) {
	select {
	case l.logChan <- &logEntry{
		now:      now,
		req:      req,
		rsp:      rsp,
		duration: duration,
	}:
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
		nowFormatted := el.now.Format(TIME_ALIGNED_NANO)
		fmt.Fprintf(l.writer, "%s - - [%s] %s %s %s %d <socketBytesWritten> %s %s <virtualhost> <totaltime> %0.6f\n", el.req.RemoteAddr, nowFormatted, el.req.Method, el.req.URL.Path, el.req.Proto, el.rsp.StatusCode, el.req.Referer(), el.req.UserAgent(), float64(el.duration)/float64(time.Millisecond))
	}
}

func logError(err error) {
	log.Print("ERROR: ", err.Error())
}
