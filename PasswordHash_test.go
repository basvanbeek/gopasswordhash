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
		if !valid {
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