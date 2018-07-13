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

func TestDeserializeTransfer(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(0)
	var fixture TestingTransferFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

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
}

func TestDeserializeSecondSignatureRegistration(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(1)
	var fixture TestingSecondSignatureRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

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

	// special case as the type 1 transaction itself has no recipientId
	publicKey, _ := PublicKeyFromHex(transaction.SenderPublicKey)
	assert.Equal(transaction.RecipientId, publicKey.ToAddress())
}

func TestDeserializeDelegateRegistration(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(2)
	var fixture TestingDelegateRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

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
}

func TestDeserializeVote(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(3)
	var fixture TestingVoteFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

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
}

func TestDeserializeMultiSignatureRegistration(t *testing.T) {
	fixtureContents := GetTransactionFixtureWithPassphrase(4)
	var fixture TestingMultiSignatureRegistrationFixture
	json.Unmarshal([]byte(fixtureContents), &fixture)

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
