// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto_test

import (
	"encoding/json"
	"testing"

	. "github.com/ArkEcosystem/go-crypto/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSerialiseTransfer(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(0)
	var fixture TestingMultiSignatureRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := crypto.DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, crypto.HexEncode(crypto.SerialiseTransaction(transaction)))
}

func TestSerialiseSecondSignatureRegistration(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(1)
	var fixture TestingMultiSignatureRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := crypto.DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, crypto.HexEncode(crypto.SerialiseTransaction(transaction)))
}

func TestSerialiseDelegateRegistration(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(2)
	var fixture TestingMultiSignatureRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := crypto.DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, crypto.HexEncode(crypto.SerialiseTransaction(transaction)))
}

func TestSerialiseVote(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(3)
	var fixture TestingMultiSignatureRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := crypto.DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, crypto.HexEncode(crypto.SerialiseTransaction(transaction)))
}

func TestSerialiseMultiSignatureRegistration(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(4)
	var fixture TestingMultiSignatureRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := crypto.DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, crypto.HexEncode(crypto.SerialiseTransaction(transaction)))
}

func TestSerialiseIpfs(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseTimelockTransfer(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseMultiPayment(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseDelegateResignation(t *testing.T) {
	t.Skip("skipping test!")
}
