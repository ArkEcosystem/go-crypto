// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func GetTransactionFixtureWithPassphrase(transactionType byte) string {
	data, _ := ioutil.ReadFile(fmt.Sprintf("./fixtures/Transactions/type-%v/passphrase.json", transactionType))

	return string(data)
}

func GetTransactionFixtureWithSecondPassphrase(transactionType byte) string {
	data, _ := ioutil.ReadFile(fmt.Sprintf("./fixtures/Transactions/type-%v/second-passphrase.json", transactionType))

	return string(data)
}

func GetIdentityFixture() TestingIdentityFixture {
	data, _ := ioutil.ReadFile("./fixtures/identity.json")

	var fixture TestingIdentityFixture
	json.Unmarshal([]byte(data), &fixture)

	return fixture
}

type TestingTransferFixture struct {
	Data struct {
		Type            uint8  `json:"type,omitempty"`
		Amount          uint64 `json:"amount,omitempty"`
		Fee             uint64 `json:"fee,omitempty"`
		RecipientId     string `json:"recipientId,omitempty"`
		Timestamp       uint32 `json:"timestamp,omitempty"`
		SenderPublicKey string `json:"senderPublicKey,omitempty"`
		Signature       string `json:"signature,omitempty"`
		Id              string `json:"id,omitempty"`
		// Asset {} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingSecondSignatureRegistrationFixture struct {
	Data struct {
		Type            uint8  `json:"type,omitempty"`
		Amount          uint64 `json:"amount,omitempty"`
		Fee             uint64 `json:"fee,omitempty"`
		RecipientId     string `json:"recipientId,omitempty"`
		Timestamp       uint32 `json:"timestamp,omitempty"`
		SenderPublicKey string `json:"senderPublicKey,omitempty"`
		Signature       string `json:"signature,omitempty"`
		Id              string `json:"id,omitempty"`
		Asset           struct {
			Signature SecondSignatureRegistrationAsset `json:"signature,omitempty"`
		} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingDelegateRegistrationFixture struct {
	Data struct {
		Type            uint8  `json:"type,omitempty"`
		Amount          uint64 `json:"amount,omitempty"`
		Fee             uint64 `json:"fee,omitempty"`
		RecipientId     string `json:"recipientId,omitempty"`
		Timestamp       uint32 `json:"timestamp,omitempty"`
		SenderPublicKey string `json:"senderPublicKey,omitempty"`
		Signature       string `json:"signature,omitempty"`
		Id              string `json:"id,omitempty"`
		Asset           struct {
			Delegate DelegateAsset `json:"delegate,omitempty"`
		} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingVoteFixture struct {
	Data struct {
		Type            uint8  `json:"type,omitempty"`
		Amount          uint64 `json:"amount,omitempty"`
		Fee             uint64 `json:"fee,omitempty"`
		RecipientId     string `json:"recipientId,omitempty"`
		Timestamp       uint32 `json:"timestamp,omitempty"`
		SenderPublicKey string `json:"senderPublicKey,omitempty"`
		Signature       string `json:"signature,omitempty"`
		Id              string `json:"id,omitempty"`
		Asset           struct {
			Votes []string `json:"votes,omitempty"`
		} `json:"asset,omitempty"`
	} `json:"data,omitempty"`
	Serialized string `json:"serialized,omitempty"`
}

type TestingMultiSignatureRegistrationFixture struct {
	Data struct {
		Type            uint8    `json:"type,omitempty"`
		Amount          uint64   `json:"amount,omitempty"`
		Fee             uint64   `json:"fee,omitempty"`
		RecipientId     string   `json:"recipientId,omitempty"`
		Timestamp       uint32   `json:"timestamp,omitempty"`
		SenderPublicKey string   `json:"senderPublicKey,omitempty"`
		Signature       string   `json:"signature,omitempty"`
		SignSignature   string   `json:"signSignature,omitempty"`
		Id              string   `json:"id,omitempty"`
		Signatures      []string `json:"signatures,omitempty"`
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
