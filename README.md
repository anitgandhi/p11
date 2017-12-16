# p11

p11 provides a wrapper on [miekg/pkcs11](https://github.com/miekg/pkcs11) by providing crypto implementations that meet the existing interfaces in the Go crypto standard library and/or x/crypto supplementary libraries.

The intent is to provide near-drop-in replacements for offloading cryptographic operations to Hardware Security Modules.

It is similar to https://github.com/thalesignite/crypto11 and https://github.com/letsencrypt/pkcs11key

## Session pool

TODO