package main

import (
	"log"

	"github.com/anitgandhi/p11"
	"github.com/anitgandhi/p11/aes"
)

func check(err) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	// TODO: remove this
	lib := "/usr/local/lib/softhsm/libsofthsm2.so"
	pin := "1234"

	ctx, err := p11.New(lib, pin, 1)
	check(err)

	block := aes.NewCipher(ctx)
}
