package main

import (
	_ "embed"
	"io/ioutil"
	"log"
	"os"
	embedCheck "stab/pkg/embed"
	"stab/pkg/manualmap"
	"strconv"
	"time"
)

func loadDll(path string, pid int) error {

	var PEBytes []byte
	var err error

	if embedCheck.IsEmbedded == true {
		PEBytes = embedCheck.EmbeddedBytes
		log.Println("Using embedded payload. Poggers!")
	} else {
		PEBytes, err = ioutil.ReadFile(path)
		if err != nil {
			log.Fatal(err)
		}
	}
	return manualmap.MemoryLoadLibrary(PEBytes, pid)
}

func main() {
	if len(os.Args) < 2 && embedCheck.IsEmbedded == false {
		log.Println("Give dll path")
		return
	}

	pid := os.Getpid()
	if len(os.Args) > 2 || (embedCheck.IsEmbedded == true && len(os.Args) > 1) {
		var err error
		if embedCheck.IsEmbedded == false {
			pid, err = strconv.Atoi(os.Args[2])
		} else {
			pid, err = strconv.Atoi(os.Args[1])
		}
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Println("Starting load...")

	if len(os.Args) > 1 {
		loadDll(os.Args[1], pid)
	} else {
		loadDll("asdfghjkl", pid)
	}

	if pid == os.Getpid() {
		time.Sleep(10 * time.Minute)
	}
}
