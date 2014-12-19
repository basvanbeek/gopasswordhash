gopasswordhash
==============

Go Password Hashing Module, for more background information on the implementation details 
and rationale, please see http://crackstation.net/hashing-security.htm

[![Build Status](https://travis-ci.org/basvanbeek/gopasswordhash.svg?branch=master)](https://travis-ci.org/basvanbeek/gopasswordhash)
[![GoDoc](https://godoc.org/github.com/basvanbeek/gopasswordhash?status.svg)](https://godoc.org/github.com/basvanbeek/gopasswordhash)

The library consists of two functions:

```
func CreateHash (password string) (string, error)
```
CreateHash creates a salted cryptographic hash with key stretching (PBKDF2), 
suitable for storage and usage in password authentication mechanisms.

```
func ValidatePassword(password string, correctHash string) bool
```
ValidatePassword hashes a password according to the setup found in the correct 
hash string and does a constant time compare on the correct hash and calculated hash.

