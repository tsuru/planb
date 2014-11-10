package main

import (
	"fmt"
	"os"
	"sync"
)

func logWriter(file *os.File, logs chan string) {
	lock := sync.Mutex{}
	for el := range logs {
		lock.Lock()
		fmt.Fprintf(file, "%s\n", el)
		file.Sync()
		lock.Unlock()
	}
}

func createLogger() (chan string, error) {
	file, err := os.OpenFile("./access.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return nil, err
	}
	logChan := make(chan string, 100)
	go logWriter(file, logChan)
	return logChan, nil
}

func logError(err error) {
	fmt.Printf("ERROR: %#v\n", err)
}
