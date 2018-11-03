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
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseTransferWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseTransferWithPassphraseAndVendorField(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase-with-vendor-field")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseTransferWithSecondPassphraseAndVendorField(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase-with-vendor-field")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)
	println(transaction.VendorFieldHex)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseTransferWithPassphraseAndVendorFieldHex(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase-with-vendor-field-hex")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseTransferWithSecondPassphraseAndVendorFieldHex(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase-with-vendor-field-hex")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseSecondSignatureRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("second_signature_registration", "passphrase")
	var fixture TestingSecondSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseDelegateRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "passphrase")
	var fixture TestingDelegateRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseDelegateRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "second-passphrase")
	var fixture TestingDelegateRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseVoteWithPassphraseWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "passphrase")
	var fixture TestingVoteFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseVoteWithPassphraseWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "second-passphrase")
	var fixture TestingVoteFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
}

func TestSerialiseMultiSignatureRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("multi_signature_registration", "second-passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	verified, _ := transaction.Verify()
	assert.Equal(fixture.Serialized, HexEncode(SerialiseTransaction(transaction)))
	assert.Equal(verified, true)
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
