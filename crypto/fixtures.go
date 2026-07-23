// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
)

func GetFile(path string) string {
	data, err := ioutil.ReadFile(path)

	if err != nil {
		log.Fatalf("Cannot read file %s: %s", path, err)
	}

	return string(data)
}

func GetFixture(file string) string {
	return GetFile(fmt.Sprintf("./fixtures/%s.json", file))
}

func GetIdentityFixture() TestingIdentityFixture {
	data := GetFixture("identity")

	var fixture TestingIdentityFixture
	_ = json.Unmarshal([]byte(data), &fixture)

	return fixture
}

func GetMessageFixture() TestingMessageFixture {
	data := GetFixture("message")

	var fixture TestingMessageFixture
	_ = json.Unmarshal([]byte(data), &fixture)

	return fixture
}

func GetBLSValidatorFixture() BLSValidatorFixture {
	data := GetFixture("bls_validator")

	var fixture BLSValidatorFixture
	_ = json.Unmarshal([]byte(data), &fixture)

	return fixture
}

func GetBLSKeysFixture() []BLSKeyFixture {
	data := GetFixture("bls_keys")

	var fixtures []BLSKeyFixture
	_ = json.Unmarshal([]byte(data), &fixtures)

	return fixtures
}

type TestingIdentityFixture struct {
	Data struct {
		PrivateKey string `json:"privateKey,omitempty"`
		PublicKey  string `json:"publicKey,omitempty"`
		Address    string `json:"address,omitempty"`
		WIF        string `json:"wif,omitempty"`
	} `json:"data,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

type TestingMessageFixture struct {
	Data struct {
		PublicKey string `json:"publickey,omitempty"`
		Signature string `json:"signature,omitempty"`
		Message   string `json:"message,omitempty"`
	} `json:"data,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}
type BLSValidatorFixture struct {
	BLSPublicKey  string `json:"bls_public_key"`
	BLSPrivateKey string `json:"bls_private_key"`
	Passphrase    string `json:"passphrase"`
}

type BLSKeyFixture struct {
	BLSPublicKey  string `json:"bls_public_key"`
	BLSPrivateKey string `json:"bls_private_key"`
	Passphrase    string `json:"passphrase"`
}
