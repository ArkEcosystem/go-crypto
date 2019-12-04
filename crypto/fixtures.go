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

func GetFixture(file string) string {
	fileName := fmt.Sprintf("./fixtures/%s.json", file)

	data, err := ioutil.ReadFile(fileName)

	if err != nil {
		log.Fatal("Cannot read fixture: ", err)
	}

	return string(data)
}

func GetTransactionFixture(transactionType string, file string) string {
	return GetFixture(fmt.Sprintf("transactions/%s/%s", transactionType, file))
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

type TestingFixture struct {
	Transaction Transaction `json:"transaction"`
	SerializedHex string `json:"serializedHex"`
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
