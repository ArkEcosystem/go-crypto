// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSerialiseTransferWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseTransferWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseTransferWithPassphraseAndVendorField(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase-with-vendor-field")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseTransferWithSecondPassphraseAndVendorField(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase-with-vendor-field")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseTransferWithPassphraseAndVendorFieldHex(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase-with-vendor-field-hex")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseTransferWithSecondPassphraseAndVendorFieldHex(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase-with-vendor-field-hex")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseSecondSignatureRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("second_signature_registration", "passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseDelegateRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseDelegateRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "second-passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseVoteWithPassphraseWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseVoteWithPassphraseWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "second-passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
}

func TestSerialiseMultiSignatureRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("multi_signature_registration", "second-passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
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
