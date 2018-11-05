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

func TestDeserializeTransferWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.RecipientId, transaction.RecipientId)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserialiseTransferWithPassphraseAndVendorFieldHex(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "passphrase-with-vendor-field-hex-2")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.RecipientId, transaction.RecipientId)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(fixture.Data.VendorFieldHex, transaction.VendorFieldHex)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserializeTransferWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("transfer", "second-passphrase")
	var fixture TestingTransferFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.RecipientId, transaction.RecipientId)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserializeSecondSignatureRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("second_signature_registration", "passphrase")
	var fixture TestingSecondSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Asset.Signature.PublicKey, transaction.Asset.Signature.PublicKey)
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)

	// special case as the type 1 transaction itself has no recipientId
	publicKey, _ := PublicKeyFromHex(transaction.SenderPublicKey)
	assert.Equal(transaction.RecipientId, publicKey.ToAddress())
}

func TestDeserializeDelegateRegistrationWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "passphrase")
	var fixture TestingDelegateRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Asset.Delegate.Username, transaction.Asset.Delegate.Username)
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserializeDelegateSecondRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("delegate_registration", "second-passphrase")
	var fixture TestingDelegateRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Asset.Delegate.Username, transaction.Asset.Delegate.Username)
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserializeVoteWithPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "passphrase")
	var fixture TestingVoteFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Asset.Votes[0], transaction.Asset.Votes[0])
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.RecipientId, transaction.RecipientId)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserializeVoteWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("vote", "second-passphrase")
	var fixture TestingVoteFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Asset.Votes[0], transaction.Asset.Votes[0])
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.RecipientId, transaction.RecipientId)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Timestamp, transaction.Timestamp)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserializeMultiSignatureRegistrationWithSecondPassphrase(t *testing.T) {
	fixtureContents := GetTransactionFixture("multi_signature_registration", "second-passphrase")
	var fixture TestingMultiSignatureRegistrationFixture
	_ = json.Unmarshal([]byte(fixtureContents), &fixture)

	transaction := DeserializeTransaction(fixture.Serialized)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Amount, transaction.Amount)
	assert.Equal(fixture.Data.Asset.MultiSignature.Keysgroup[0], transaction.Asset.MultiSignature.Keysgroup[0])
	assert.Equal(fixture.Data.Asset.MultiSignature.Keysgroup[1], transaction.Asset.MultiSignature.Keysgroup[1])
	assert.Equal(fixture.Data.Asset.MultiSignature.Keysgroup[2], transaction.Asset.MultiSignature.Keysgroup[2])
	assert.Equal(fixture.Data.Asset.MultiSignature.Lifetime, transaction.Asset.MultiSignature.Lifetime)
	assert.Equal(fixture.Data.Asset.MultiSignature.Min, transaction.Asset.MultiSignature.Min)
	assert.Equal(fixture.Data.Fee, transaction.Fee)
	assert.Equal(fixture.Data.Id, transaction.Id)
	assert.Equal(fixture.Data.SenderPublicKey, transaction.SenderPublicKey)
	assert.Equal(fixture.Data.Signature, transaction.Signature)
	assert.Equal(fixture.Data.Signatures[0], transaction.Signatures[0])
	assert.Equal(fixture.Data.Signatures[1], transaction.Signatures[1])
	assert.Equal(fixture.Data.Signatures[2], transaction.Signatures[2])
	assert.Equal(fixture.Data.SignSignature, transaction.SignSignature)
	assert.Equal(fixture.Data.Type, transaction.Type)
	assert.Equal(uint8(23), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)

	success, _ := transaction.Verify()
	assert.Equal(success, true)
}

func TestDeserializeIpfs(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserializeTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}

func TestDeserializeTimelockTransfer(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserializeTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}

func TestDeserializeMultiPayment(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserializeTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}

func TestDeserializeDelegateResignation(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserializeTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}
