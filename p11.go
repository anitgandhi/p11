// package p11 provides cryptographic algorithm implementations
// that meet the interfaces found in the crypto standard library,
// but are backed by an HSM.
// This provides an easy plug-and-play abstraction for common
// crypto operations.
// inspired by github.com/letsencrypt/pkcs11key

package p11

import (
	"github.com/miekg/pkcs11"
)

type Context struct {
	HSM *pkcs11.Ctx

	// TODO: make this a pool of sessions, default of size 1
	Session pkcs11.SessionHandle
}

func New(lib string, pin string, sessionPoolSize int) (*Context, error) {
	ctx := Context{}

	ctx.HSM = pkcs11.New(lib)

	err := ctx.HSM.Initialize()
	if err != nil {
		return nil, err
	}

	slots, err := ctx.HSM.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	ctx.Session, err = ctx.HSM.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}

	err = ctx.HSM.Login(ctx.Session, pkcs11.CKU_USER, pin)
	if err != nil {
		return nil, err
	}

	return &ctx, nil
}

func (c *Context) Destroy() {
	// Log out of and close all sessions
	c.HSM.Logout(c.Session)
	c.HSM.CloseSession(c.Session)

	// Global Cleanup
	c.HSM.Finalize()
	c.HSM.Destroy()
}

func (c *Context) GetSession() pkcs11.SessionHandle {
	return 0
}

func (c *Context) PutSession(pkcs11.SessionHandle) {

}

// Useful helper functions

// FindObjectByID searches for a token object by CKA_ID and returns the object handle
func (c *Context) FindObjectByID(id string) (pkcs11.ObjectHandle, error) {
	return 0, nil
}

// FindObjectByLabel searches for a token object by CKA_LABEL and returns the object handle
func (c *Context) FindObjectByLabel(label string) (pkcs11.ObjectHandle, error) {
	return 0, nil
}

// FindObjectByTemplate searches for a token object by the attribute template and returns the object handle
func (c *Context) FindObjectByTemplate(template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, nil
}
