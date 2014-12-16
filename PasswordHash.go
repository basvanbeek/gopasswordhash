/*

The MIT License (MIT)

Copyright (c) 2014 Bas van Beek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Password Hashing With PBKDF2 (implementation logic see http://crackstation.net/hashing-security.htm).
*/

package gopasswordhash

import (
	"fmt"
	"errors"
	"strings"
	"strconv"
	"encoding/base64"
	"crypto/rand"
	"crypto/subtle"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	
	"golang.org/x/crypto/pbkdf2"
)

// these constants may be changed without breaking existing hashes.
const PBKDF2_HASH_ALGORITHM string = "sha512"
const PBKDF2_ITERATIONS     int    = 4096
const PBKDF2_SALT_BYTES     int    = 64
const PBKDF2_HASH_BYTES     int    = 64

const HASH_SECTIONS         int    = 4
const HASH_ALGORITHM_INDEX  int    = 0
const HASH_ITERATION_INDEX  int    = 1
const HASH_SALT_INDEX       int    = 2
const HASH_PBKDF2_INDEX     int    = 3

func CreateHash(password string) (string, error) {
	salt := make([]byte, PBKDF2_SALT_BYTES)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	var hash []byte
	switch PBKDF2_HASH_ALGORITHM {
		default:
			return "", errors.New("invalid hash algorithm selected")
		case "sha1":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, PBKDF2_HASH_BYTES, sha1.New)
		case "sha224":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, PBKDF2_HASH_BYTES, sha256.New224)
		case "sha256":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, PBKDF2_HASH_BYTES, sha256.New)
		case "sha384":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, PBKDF2_HASH_BYTES, sha512.New384)
		case "sha512":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, PBKDF2_HASH_BYTES, sha512.New)
	}

	/* format: algorithm:iterations:salt:hash */
	return fmt.Sprintf(
		"%s:%d:%s:%s", PBKDF2_HASH_ALGORITHM, PBKDF2_ITERATIONS, 
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash),
	), err
}

func ValidatePassword(password string, goodHash string) bool {
	params := strings.Split(goodHash, ":")
	if len(params) < HASH_SECTIONS {
		return false
	}
	it, err := strconv.Atoi(params[HASH_ITERATION_INDEX])
	if err != nil {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(params[HASH_SALT_INDEX])
	if err != nil {
		return false
	}
	pbkdf2Hash, err := base64.StdEncoding.DecodeString(params[HASH_PBKDF2_INDEX])
	if err != nil {
		return false
	}
	var hash []byte
	switch params[HASH_ALGORITHM_INDEX] {
		default:
			return false
		case "sha1":
			hash = pbkdf2.Key([]byte(password), salt, it, len(pbkdf2Hash), sha1.New)
		case "sha224":
			hash = pbkdf2.Key([]byte(password), salt, it, len(pbkdf2Hash), sha256.New224)
		case "sha256":
			hash = pbkdf2.Key([]byte(password), salt, it, len(pbkdf2Hash), sha256.New)
		case "sha384":
			hash = pbkdf2.Key([]byte(password), salt, it, len(pbkdf2Hash), sha512.New384)
		case "sha512":
			hash = pbkdf2.Key([]byte(password), salt, it, len(pbkdf2Hash), sha512.New)
	}
	return subtle.ConstantTimeCompare(hash, pbkdf2Hash) == 1
}


