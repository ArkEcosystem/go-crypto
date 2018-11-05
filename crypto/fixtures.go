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
)

func GetFixture(file string) string {
	data, _ := ioutil.ReadFile(fmt.Sprintf("./fixtures/%s.json", file))

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

type TestingTransferFixture struct {
	Data struct {
		Type            uint8     `json:"type,omitempty"`
		Network         uint8     `json:"network,omitempty"`
		Version         uint8     `json:"version,omitempty"`
		Amount          FlexToshi `json:"amount,omitempty"`
		Fee             FlexToshi `json:"fee,omitempty"`
		RecipientId     string    `json:"recipientId,omitempty"`
		Timestamp       int32     `json:"timestamp,omitempty"`
		SenderPublicKey string    `json:"senderPublicKey,omitempty"`
		Signature       string    `json:"signature,omitempty"`
		Id              string    `json:"id,omitempty"`
		VendorFieldHex  string    `json:"vendorFieldHex,omitempty"`
		// Asset {} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingSecondSignatureRegistrationFixture struct {
	Data struct {
		Type            uint8     `json:"type,omitempty"`
		Network         uint8     `json:"network,omitempty"`
		Version         uint8     `json:"version,omitempty"`
		Amount          FlexToshi `json:"amount,omitempty"`
		Fee             FlexToshi `json:"fee,omitempty"`
		RecipientId     string    `json:"recipientId,omitempty"`
		Timestamp       int32     `json:"timestamp,omitempty"`
		SenderPublicKey string    `json:"senderPublicKey,omitempty"`
		Signature       string    `json:"signature,omitempty"`
		Id              string    `json:"id,omitempty"`
		Asset           struct {
			Signature SecondSignatureRegistrationAsset `json:"signature,omitempty"`
		} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingDelegateRegistrationFixture struct {
	Data struct {
		Type            uint8     `json:"type,omitempty"`
		Network         uint8     `json:"network,omitempty"`
		Version         uint8     `json:"version,omitempty"`
		Amount          FlexToshi `json:"amount,omitempty"`
		Fee             FlexToshi `json:"fee,omitempty"`
		RecipientId     string    `json:"recipientId,omitempty"`
		Timestamp       int32     `json:"timestamp,omitempty"`
		SenderPublicKey string    `json:"senderPublicKey,omitempty"`
		Signature       string    `json:"signature,omitempty"`
		Id              string    `json:"id,omitempty"`
		Asset           struct {
			Delegate DelegateAsset `json:"delegate,omitempty"`
		} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingVoteFixture struct {
	Data struct {
		Type            uint8     `json:"type,omitempty"`
		Network         uint8     `json:"network,omitempty"`
		Version         uint8     `json:"version,omitempty"`
		Amount          FlexToshi `json:"amount,omitempty"`
		Fee             FlexToshi `json:"fee,omitempty"`
		RecipientId     string    `json:"recipientId,omitempty"`
		Timestamp       int32     `json:"timestamp,omitempty"`
		SenderPublicKey string    `json:"senderPublicKey,omitempty"`
		Signature       string    `json:"signature,omitempty"`
		Id              string    `json:"id,omitempty"`
		Asset           struct {
			Votes []string `json:"votes,omitempty"`
		} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingMultiSignatureRegistrationFixture struct {
	Data struct {
		Type            uint8     `json:"type,omitempty"`
		Network         uint8     `json:"network,omitempty"`
		Version         uint8     `json:"version,omitempty"`
		Amount          FlexToshi `json:"amount,omitempty"`
		Fee             FlexToshi `json:"fee,omitempty"`
		RecipientId     string    `json:"recipientId,omitempty"`
		Timestamp       int32     `json:"timestamp,omitempty"`
		SenderPublicKey string    `json:"senderPublicKey,omitempty"`
		Signature       string    `json:"signature,omitempty"`
		SignSignature   string    `json:"signSignature,omitempty"`
		Id              string    `json:"id,omitempty"`
		Signatures      []string  `json:"signatures,omitempty"`
		Asset           struct {
			MultiSignature MultiSignatureRegistrationAsset `json:"multisignature,omitempty"`
		} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
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
