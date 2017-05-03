package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

const usage = `
usage:
	hmac sign|verify <key> <value>
`

func main() {
	if len(os.Args) < 4 ||
		(os.Args[1] != "sign" && os.Args[1] != "verify") {
		fmt.Println(usage)
		os.Exit(1)
	}

	cmd := os.Args[1]   // sign or verify
	key := os.Args[2]   // grab key
	value := os.Args[3] // grab value

	switch cmd {
	case "sign":

		v := []byte(value)
		// creates a new hash method algorithm to call
		// sha256 is a hashing algorithm
		h := hmac.New(sha256.New, []byte(key))
		h.Write(v)
		sig := h.Sum(nil)

		buf := make([]byte, len(v)+len(sig))
		copy(buf, v)
		// copy sig into last part of buf
		copy(buf[len(v):], sig)

		// URL encoding changes the base64 '/' and '+' characters to other
		// characters that won't screw with the URL
		fmt.Println(base64.URLEncoding.EncodeToString(buf))

	case "verify":
		buf, err := base64.URLEncoding.DecodeString(value)
		if err != nil {
			fmt.Printf("error decoding: %v\n", err)
			os.Exit(1)
		}
		v := buf[:len(buf)-sha256.Size]   // from start to size of sha256
		sig := buf[len(buf)-sha256.Size:] // from size of sha256 to end

		h := hmac.New(sha256.New, []byte(key))
		h.Write(v)
		sig2 := h.Sum(nil)
		if hmac.Equal(sig, sig2) {
			fmt.Println("signature is valid!")
		} else {
			fmt.Println("INVALID SIGNATURE")
		}
	}
}
