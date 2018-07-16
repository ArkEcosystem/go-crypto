// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto_test

import (
	"testing"

	. "github.com/ArkEcosystem/go-crypto/crypto"
	"github.com/stretchr/testify/assert"
)

func TestBuildTransferWithPassphrase(t *testing.T) {
	transaction := crypto.BuildTransfer(
		"AXoXnFi4z1Z6aFvjEYkDVCtBGW2PaRiM25",
		uint64(133380000000),
		"This is a transaction from Go",
		"This is a top secret passphrase",
		"",
	)

	assert := assert.New(t)
	assert.True(crypto.transaction.Verify())
}

func TestBuildTransferWithSecondPassphrase(t *testing.T) {
	transaction := crypto.BuildTransfer(
		"AXoXnFi4z1Z6aFvjEYkDVCtBGW2PaRiM25",
		uint64(133380000000),
		"This is a transaction from Go",
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(crypto.transaction.Verify())

	secondPublicKey, _ := PublicKeyFromPassphrase("this is a top secret second passphrase")
	assert.True(crypto.transaction.SecondVerify(secondPublicKey))
}

func TestBuildSecondSignatureRegistration(t *testing.T) {
	transaction := crypto.BuildSecondSignatureRegistration(
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(crypto.transaction.Verify())
}

func TestBuildDelegateRegistrationWithPassphrase(t *testing.T) {
	transaction := crypto.BuildDelegateRegistration(
		"polopolo",
		"lumber desk thought industry island man slow vendor pact fragile enact season",
		"",
	)

	assert := assert.New(t)
	assert.True(crypto.transaction.Verify())
}

func TestBuildDelegateRegistrationWithSecondPassphrase(t *testing.T) {
	transaction := crypto.BuildDelegateRegistration(
		"polopolo",
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(crypto.transaction.Verify())

	secondPublicKey, _ := PublicKeyFromPassphrase("this is a top secret second passphrase")
	assert.True(crypto.transaction.SecondVerify(secondPublicKey))
}

func TestBuildVoteWithPassphrase(t *testing.T) {
	transaction := crypto.BuildVote(
		"+034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192",
		"This is a top secret passphrase",
		"",
	)

	assert := assert.New(t)
	assert.True(crypto.transaction.Verify())
}

func TestBuildVoteWithSecondPassphrase(t *testing.T) {
	transaction := crypto.BuildVote(
		"+034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192",
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(crypto.transaction.Verify())

	secondPublicKey, _ := PublicKeyFromPassphrase("this is a top secret second passphrase")
	assert.True(crypto.transaction.SecondVerify(secondPublicKey))
}
