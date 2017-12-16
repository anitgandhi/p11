package main

import (
	"log"

	"github.com/anitgandhi/p11"
	"github.com/miekg/pkcs11"
)

func check(err) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	lib := "/usr/local/lib/softhsm/libsofthsm2.so"
	pin := "1234"

	ctx, err := p11.New(lib, pin, 1)
	check(err)

	defer ctx.Destroy()

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute()
	}
}
