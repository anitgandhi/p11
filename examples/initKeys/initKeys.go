package main

import (
	"log"

	"github.com/anitgandhi/p11"
	"github.com/miekg/pkcs11"
)

func check(err error) {
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

	keyid := "19"

	// This is an AES key with a known value, used for testing
	aesKeyTemplate := []*pkcs11.Attribute{

		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),

		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),

		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyid),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyid),

		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),

		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),

		pkcs11.NewAttribute(pkcs11.CKA_VALUE, []byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}),
	}

	oh, err := ctx.HSM.CreateObject(ctx.Session, aesKeyTemplate)
	check(err)

	log.Println("object handle", oh)

}
