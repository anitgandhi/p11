package aes

import (
	"testing"

	"github.com/anitgandhi/p11"
	"github.com/miekg/pkcs11"
)

var (
	p11Ctx *p11.Context
)

func init() {
	lib := "/usr/local/lib/softhsm/libsofthsm2.so"
	pin := "1234"

	p11Ctx, _ = p11.New(lib, pin, 1)
}

func createKey(key []byte, keyid string) (pkcs11.ObjectHandle, error) {
	// This is an AES key with a known value, used for testing
	aesKeyTemplate := []*pkcs11.Attribute{

		// create it as a temporary session key only
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),

		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES),

		pkcs11.NewAttribute(pkcs11.CKA_LABEL, keyid),
		pkcs11.NewAttribute(pkcs11.CKA_ID, keyid),

		pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
		pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),

		pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
		pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true),

		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key),
	}

	return p11Ctx.HSM.CreateObject(p11Ctx.Session, aesKeyTemplate)
}

func deleteKey(oh pkcs11.ObjectHandle) error {
	return p11Ctx.HSM.DestroyObject(p11Ctx.Session, oh)
}

// The below test code is copied from the Go standard library crypto/aes_test.go,
// but is slightly modified to use PKCS11 to create temporary key objects

// Appendix B, C of FIPS 197: Cipher examples, Example vectors.
type CryptTest struct {
	key []byte
	in  []byte
	out []byte
}

var encryptTests = []CryptTest{
	{
		// Appendix B.
		[]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c},
		[]byte{0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34},
		[]byte{0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32},
	},
	{
		// Appendix C.1.  AES-128
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[]byte{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a},
	},
	{
		// Appendix C.2.  AES-192
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		},
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[]byte{0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91},
	},
	{
		// Appendix C.3.  AES-256
		[]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[]byte{0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89},
	},
}

// Test Cipher Encrypt method against FIPS 197 examples.
func TestCipherEncrypt(t *testing.T) {
	for i, tt := range encryptTests {
		// create the temporary key object in the HSM
		oh, err := createKey(tt.key, "19")
		if err != nil {
			t.Errorf("createKey(%d bytes) = %s", len(tt.key), err)
			deleteKey(oh)
			continue
		}

		c, err := NewCipher(p11Ctx, oh)
		if err != nil {
			t.Errorf("NewCipher(%d bytes) = %s", len(tt.key), err)
			deleteKey(oh)
			continue
		}
		out := make([]byte, len(tt.in))
		c.Encrypt(out, tt.in)
		for j, v := range out {
			if v != tt.out[j] {
				t.Errorf("Cipher.Encrypt %d: out[%d] = %#x, want %#x", i, j, v, tt.out[j])
				deleteKey(oh)
				break
			}
		}

		deleteKey(oh)
	}
}

// Test Cipher Decrypt against FIPS 197 examples.
func TestCipherDecrypt(t *testing.T) {
	for i, tt := range encryptTests {
		// create the temporary key object in the HSM
		oh, err := createKey(tt.key, "19")
		if err != nil {
			t.Errorf("createKey(%d bytes) = %s", len(tt.key), err)
			deleteKey(oh)
			continue
		}

		c, err := NewCipher(p11Ctx, oh)
		if err != nil {
			t.Errorf("NewCipher(%d bytes) = %s", len(tt.key), err)
			deleteKey(oh)
			continue
		}
		plain := make([]byte, len(tt.in))
		c.Decrypt(plain, tt.out)
		for j, v := range plain {
			if v != tt.in[j] {
				t.Errorf("decryptBlock %d: plain[%d] = %#x, want %#x", i, j, v, tt.in[j])
				deleteKey(oh)
				break
			}
		}
		deleteKey(oh)
	}
}

// Test short input/output.
// Assembly used to not notice.
// See issue 7928.
func TestShortBlocks(t *testing.T) {
	bytes := func(n int) []byte { return make([]byte, n) }

	oh, err := createKey(bytes(16), "19")
	if err != nil {
		t.Errorf("createKey(%d bytes) = %s", 16, err)
		deleteKey(oh)
	}

	c, _ := NewCipher(p11Ctx, oh)

	mustPanic(t, "crypto/aes: input not full block", func() { c.Encrypt(bytes(1), bytes(1)) })
	mustPanic(t, "crypto/aes: input not full block", func() { c.Decrypt(bytes(1), bytes(1)) })
	mustPanic(t, "crypto/aes: input not full block", func() { c.Encrypt(bytes(100), bytes(1)) })
	mustPanic(t, "crypto/aes: input not full block", func() { c.Decrypt(bytes(100), bytes(1)) })
	mustPanic(t, "crypto/aes: output not full block", func() { c.Encrypt(bytes(1), bytes(100)) })
	mustPanic(t, "crypto/aes: output not full block", func() { c.Decrypt(bytes(1), bytes(100)) })

	deleteKey(oh)
}

func mustPanic(t *testing.T, msg string, f func()) {
	defer func() {
		err := recover()
		if err == nil {
			t.Errorf("function did not panic, wanted %q", msg)
		} else if err != msg {
			t.Errorf("got panic %v, wanted %q", err, msg)
		}
	}()
	f()
}

func BenchmarkEncrypt(b *testing.B) {
	tt := encryptTests[0]

	oh, err := createKey(tt.key, "19")
	if err != nil {
		b.Errorf("createKey(%d bytes) = %s", len(tt.key), err)
		deleteKey(oh)
	}

	c, err := NewCipher(p11Ctx, oh)
	if err != nil {
		deleteKey(oh)
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.in))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(out, tt.in)
	}

	deleteKey(oh)
}

func BenchmarkDecrypt(b *testing.B) {
	tt := encryptTests[0]

	oh, err := createKey(tt.key, "19")
	if err != nil {
		b.Errorf("createKey(%d bytes) = %s", len(tt.key), err)
		deleteKey(oh)
	}

	c, err := NewCipher(p11Ctx, oh)
	if err != nil {
		deleteKey(oh)
		b.Fatal("NewCipher:", err)
	}
	out := make([]byte, len(tt.out))
	b.SetBytes(int64(len(out)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(out, tt.out)
	}

	deleteKey(oh)
}
