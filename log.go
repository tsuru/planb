package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

type Logger struct {
	logChan chan string
	done    chan bool
	writer  io.WriteCloser
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
		logChan: make(chan string, 10000),
		done:    make(chan bool),
		writer:  writer,
	}
	go l.logWriter()
	return &l
}

func (l *Logger) Message(msg string) {
	select {
	case l.logChan <- msg:
	default:
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
		fmt.Fprintln(l.writer, el)
	}
}

func logError(err error) {
	log.Print("ERROR:", err.Error())
}
