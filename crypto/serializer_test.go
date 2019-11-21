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
	fixtureContents := GetTransactionFixture("transfer", "passphrase-no-vendor-field")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseTransferWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase-no-vendor-field")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseTransferWithPassphraseAndVendorField(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase-with-vendor-field")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseTransferWithSecondPassphraseAndVendorField(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase-with-vendor-field")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseSecondSignatureRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("second_signature_registration", "passphrase-no-vendor-field")
	var fixture TestingSecondSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseDelegateRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "passphrase-no-vendor-field")
	var fixture TestingDelegateRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseDelegateRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "second-passphrase-no-vendor-field")
	var fixture TestingDelegateRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseVoteWithPassphraseWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "passphrase-no-vendor-field")
	var fixture TestingVoteFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerialiseVoteWithPassphraseWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "second-passphrase-no-vendor-field")
	var fixture TestingVoteFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

/*
func TestSerialiseMultiSignatureRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("multi_signature_registration", "second-passphrase-no-vendor-field")
	var fixture TestingMultiSignatureRegistrationFixture
	var transactionObject Transaction
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)
	var fixtureContentsData []byte
	fixtureContentsData, _ = json.Marshal(fixture.Data)
	_ = json.Unmarshal(fixtureContentsData, &transactionObject)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)

	assert.Equal(fixture.Serialized, HexEncode(transactionObject.serialize(true, true)))
	assert.Equal(fixture.Serialized, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}
*/

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
