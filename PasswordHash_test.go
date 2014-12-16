// Password Hashing With PBKDF2 (http://crackstation.net/hashing-security.htm).

package gopasswordhash

import (
	"fmt"
	"testing"
)

func testHash(t *testing.T, password string) {
	retVal, err := CreateHash(password)
	if err != nil {
		t.Errorf("GoPasswordHash.CreateHash(\"%s\"): expected a hash, got error: %s", password, err)
	} else {
		fmt.Printf("Created Hash %s (len: %d) from password: %s\n", retVal, len(retVal), password)
		valid := ValidatePassword(password, retVal)
		if valid != true {
			t.Errorf("GoPasswordHash.ValidatePassword(\"%s, %s\"): expected true, got false", password, retVal)
		}
	}
}

func TestWithEmptyPass(t *testing.T) {
	testHash(t, "")
}

func TestWithShortPass(t *testing.T) {
	testHash(t, "sh0rtPa55")
}

func TestWithLongPass(t *testing.T) {
	testHash(t, "uliGHOIUYG59(&^%5&^%7tgukyHJgkjhGJHkgKHJgjhkGKhgghjkGgjhkg6T76r&^f65%^6%^r865%^r56kjhVkjh^&%&gkhgiluy98)(890^$%3765YUT65e6uRIugJKH}}{P[][")
}