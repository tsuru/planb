// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package log

import (
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"os"
	"strings"
	"time"
)

const (
	TIME_HIPACHE_MODE = "02/Jan/2006:15:04:05 -0700"
)

var (
	ErrorLogger = log.New(os.Stderr, "", log.LstdFlags)
)

type Logger struct {
	logChan    chan *LogEntry
	done       chan bool
	writer     io.WriteCloser
	nextNotify <-chan time.Time
}

type LogEntry struct {
	Now             time.Time
	BackendDuration time.Duration
	TotalDuration   time.Duration
	BackendKey      string
	RemoteAddr      string
	Method          string
	Path            string
	Proto           string
	Referer         string
	UserAgent       string
	RequestIDHeader string
	RequestID       string
	StatusCode      int
	ContentLength   int64
}

func NewFileLogger(path string) (*Logger, error) {
	if path == "syslog" {
		return NewSyslogLogger()
	} else if path == "stdout" {
		return NewStdoutLogger()
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

type syncCloser struct{ *os.File }

func (n syncCloser) Close() error { return n.Sync() }

func NewStdoutLogger() (*Logger, error) {
	return NewWriterLogger(syncCloser{os.Stdout}), nil
}

func NewWriterLogger(writer io.WriteCloser) *Logger {
	l := Logger{
		logChan:    make(chan *LogEntry, 10000),
		done:       make(chan bool),
		writer:     writer,
		nextNotify: time.After(0),
	}
	go l.logWriter()
	return &l
}

func (l *Logger) MessageRaw(entry *LogEntry) {
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
		nowFormatted := el.Now.Format(TIME_HIPACHE_MODE)
		ip, _, _ := net.SplitHostPort(el.RemoteAddr)
		if ip == "" {
			ip = el.RemoteAddr
		}
		if !strings.HasPrefix(ip, "::") {
			ip = "::ffff:" + ip
		}
		fmt.Fprintf(l.writer,
			"%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\" \"%s:%s\" \"%s\" %0.3f %0.3f\n",
			ip,
			nowFormatted,
			el.Method,
			el.Path,
			el.Proto,
			el.StatusCode,
			el.ContentLength,
			el.Referer,
			el.UserAgent,
			el.RequestIDHeader,
			el.RequestID,
			el.BackendKey,
			float64(el.TotalDuration)/float64(time.Second),
			float64(el.BackendDuration)/float64(time.Second),
		)
	}
}

func LogError(location string, path string, err error) {
	ErrorLogger.Print("ERROR in ", location, " - ", path, " - ", err.Error())
}
