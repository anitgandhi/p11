# p11

p11 provides a wrapper on [miekg/pkcs11](https://github.com/miekg/pkcs11) by providing crypto implementations that meet the existing interfaces in the Go crypto standard library and/or x/crypto supplementary libraries.

The intent is to provide near-drop-in replacements for offloading _symmetric_ cryptographic operations to Hardware Security Modules.

It is similar to https://github.com/thalesignite/crypto11 and https://github.com/letsencrypt/pkcs11key . The key difference is that those libraries offer implementations for the common _assymmetric_ operations, while this library is for _symmetric_ operations.

HSMs aren't often used for symmetric operations so this is really just for fun/proof-of-concept. As such, please don't use this in production.

## Working

AES (ECB)

## TODO

- [ ] integrate miekg/pkcs11/p11 for the session and context management to reduce implementation fragmentation
- [ ] implement CBC cipher.BlockMode interface
- [ ] implement GCM cipher.AEAD interface
- [x] add AES ECB unit tests
