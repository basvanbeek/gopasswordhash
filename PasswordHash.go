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
*/

/* 
	Package gopasswordhash implements functions to create and verify salted cryptographic hashes suitable 
	for building password authentication mechanisms. Code has been inspired by the excellent article 
	"Salted Password Hashing - Doing it Right" which can be found at https://crackstation.net/hashing-security.htm
	
	When needing highly secure password verification / storage solutions use this library in combination with
	a secret key to be added to the password which should be stored on an external system or
	special hardware device like the YubiHSM
*/
package gopasswordhash

import (
	"fmt"
	"errors"
	"strings"
	"strconv"
	"encoding/base64"
	"crypto/subtle"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/pbkdf2"
)

/* The PBKDF2_* and SCRYPT_* constants may be changed without breaking existing stored hashes. */
const (
	// PBKDF2_HASH_ALGORITHM can be set to sha1, sha224, sha256, sha384 or sha512 as the underlying hashing mechanism to be used by the PBKDF2 function
	PBKDF2_HASH_ALGORITHM string = "sha512"
	// PBKDF2_ITERATIONS sets the amount of iterations used by the PBKDF2 hashing algorithm
	PBKDF2_ITERATIONS     int    = 15000
	// SCRYPT_N is a CPU/memory cost parameter, which must be a power of two greater than 1
	SCRYPT_N              int    = 32768
	// SCRYPT_R is the block size parameter
	SCRYPT_R              int    = 8
	// SCRYPT_P is the parallelization parameter, a positive integer less than or equal to ((2^32-1) * 32) / (128 * r)
	SCRYPT_P              int    = 1
	
	// SALT_BYTES sets the amount of bytes for the salt used in the PBKDF2 / scrypt hashing algorithm
	SALT_BYTES            int    = 64
	// HASH_BYTES sets the amount of bytes for the hash output from the PBKDF2 / scrypt hashing algorithm
	HASH_BYTES            int    = 64
)

/* altering the HASH_* constants breaks existing stored hashes */
const (
	// HASH_SECTIONS identifies the expected amount of parameters encoded in a hash generated and/or tested in this package
	HASH_SECTIONS         int    = 4
	// HASH_ALGORITHM_INDEX identifies the position of the hash algorithm identifier in a hash generated and/or tested in this package
	HASH_ALGORITHM_INDEX  int    = 0
	// HASH_ITERATION_INDEX identifies the position of the iteration count used by PBKDF2 in a hash generated and/or tested in this package
	HASH_ITERATION_INDEX  int    = 1
	// HASH_SALT_INDEX identifies the position of the used salt in a hash generated and/or tested in this package
	HASH_SALT_INDEX       int    = 2
	// HASH_PBKDF2_INDEX identifies the position of the actual password hash in a hash generated and/or tested in this package
	HASH_PBKDF2_INDEX     int    = 3
	// HASH_SCRYPT_R_INDEX identifies the position of the scrypt block size parameter in a hash generated and/or tested in this package
	HASH_SCRYPT_R_INDEX   int    = 4
	// HASH_SCRYPT_R_INDEX identifies the position of the scrypt parallelization parameter in a hash generated and/or tested in this package
	HASH_SCRYPT_P_INDEX   int    = 5
)

// CreateHash creates a salted cryptographic hash with key stretching (PBKDF2), suitable for storage and usage in password authentication mechanisms.
func CreateHash(password string) (string, error) {
	salt := make([]byte, SALT_BYTES)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}
	var hash []byte
	switch PBKDF2_HASH_ALGORITHM {
		default:
			return "", errors.New("invalid hash algorithm selected")
		case "sha1":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, HASH_BYTES, sha1.New)
		case "sha224":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, HASH_BYTES, sha256.New224)
		case "sha256":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, HASH_BYTES, sha256.New)
		case "sha384":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, HASH_BYTES, sha512.New384)
		case "sha512":
			hash = pbkdf2.Key([]byte(password), salt, PBKDF2_ITERATIONS, HASH_BYTES, sha512.New)
		case "scrypt":
			hash, err = scrypt.Key([]byte(password), salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, HASH_BYTES) 
			if err != nil {
				return "", err
			}
			/* format: algorithm:cpu/mem cost:salt:hash:R(blocksize):P(parallelization) */
			return fmt.Sprintf(
				"%s:%d:%s:%s:%d:%d", PBKDF2_HASH_ALGORITHM, SCRYPT_N, 
				base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash),
				SCRYPT_R, SCRYPT_P,
			), err
	}

	/* format: algorithm:iterations:salt:hash */
	return fmt.Sprintf(
		"%s:%d:%s:%s", PBKDF2_HASH_ALGORITHM, PBKDF2_ITERATIONS, 
		base64.StdEncoding.EncodeToString(salt), base64.StdEncoding.EncodeToString(hash),
	), err
}

// ValidatePassword hashes a password according to the setup found in the correct hash string and does a constant time compare on the correct hash and calculated hash.
func ValidatePassword(password string, correctHash string) bool {
	params := strings.Split(correctHash, ":")
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
	hash, err := base64.StdEncoding.DecodeString(params[HASH_PBKDF2_INDEX])
	if err != nil {
		return false
	}

	var testHash []byte
	switch params[HASH_ALGORITHM_INDEX] {
		default:
			return false
		case "sha1":
			testHash = pbkdf2.Key([]byte(password), salt, it, len(hash), sha1.New)
		case "sha224":
			testHash = pbkdf2.Key([]byte(password), salt, it, len(hash), sha256.New224)
		case "sha256":
			testHash = pbkdf2.Key([]byte(password), salt, it, len(hash), sha256.New)
		case "sha384":
			testHash = pbkdf2.Key([]byte(password), salt, it, len(hash), sha512.New384)
		case "sha512":
			testHash = pbkdf2.Key([]byte(password), salt, it, len(hash), sha512.New)
		case "scrypt":
			r, err := strconv.Atoi(params[HASH_SCRYPT_R_INDEX])
			if err != nil {
				return false
			}
			p, err := strconv.Atoi(params[HASH_SCRYPT_P_INDEX])
			if err != nil {
				return false
			}
			testHash, err = scrypt.Key([]byte(password), salt, it, r, p, len(hash))
	}
	return subtle.ConstantTimeCompare(hash, testHash) == 1
}
