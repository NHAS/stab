package main

import (
	"io/ioutil"
	"log"
	"os"
	"reflectivePEdll/pkg/manualmap"
	"strconv"
	"time"
)

func loadDll(path string, pid int) error {

	PEBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	return manualmap.MemoryLoadLibrary(PEBytes, pid)
}

func main() {
	if len(os.Args) < 2 {
		log.Println("Give dll path")
		return
	}

	pid := os.Getpid()
	if len(os.Args) > 2 {
		var err error
		pid, err = strconv.Atoi(os.Args[2])
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Starting load...")

	log.Println(loadDll(os.Args[1], pid))

	if pid == os.Getpid() {
		time.Sleep(10 * time.Minute)
	}
}
