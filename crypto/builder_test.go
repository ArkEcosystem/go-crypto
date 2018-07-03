// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBuildTransferWithSecret(t *testing.T) {
	transaction := BuildTransfer(
		"AXoXnFi4z1Z6aFvjEYkDVCtBGW2PaRiM25",
		uint64(133380000000),
		"This is a transaction from Go",
		"This is a top secret passphrase",
		"",
	)

	assert := assert.New(t)
	assert.True(transaction.Verify())
}

func TestBuildTransferWithSecondSecret(t *testing.T) {
	transaction := BuildTransfer(
		"AXoXnFi4z1Z6aFvjEYkDVCtBGW2PaRiM25",
		uint64(133380000000),
		"This is a transaction from Go",
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(transaction.Verify())

	secondPublicKey, _ := PublicKeyFromSecret("this is a top secret second passphrase")
	assert.True(transaction.SecondVerify(secondPublicKey))
}

func TestBuildSecondSignatureRegistration(t *testing.T) {
	transaction := BuildSecondSignatureRegistration(
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(transaction.Verify())
}

func TestBuildDelegateRegistrationWithSecret(t *testing.T) {
	transaction := BuildDelegateRegistration(
		"polopolo",
		"lumber desk thought industry island man slow vendor pact fragile enact season",
		"",
	)

	assert := assert.New(t)
	assert.True(transaction.Verify())
}

func TestBuildDelegateRegistrationWithSecondSecret(t *testing.T) {
	transaction := BuildDelegateRegistration(
		"polopolo",
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(transaction.Verify())

	secondPublicKey, _ := PublicKeyFromSecret("this is a top secret second passphrase")
	assert.True(transaction.SecondVerify(secondPublicKey))
}

func TestBuildVoteWithSecret(t *testing.T) {
	transaction := BuildVote(
		"+034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192",
		"This is a top secret passphrase",
		"",
	)

	assert := assert.New(t)
	assert.True(transaction.Verify())
}

func TestBuildVoteWithSecondSecret(t *testing.T) {
	transaction := BuildVote(
		"+034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192",
		"This is a top secret passphrase",
		"this is a top secret second passphrase",
	)

	assert := assert.New(t)
	assert.True(transaction.Verify())

	secondPublicKey, _ := PublicKeyFromSecret("this is a top secret second passphrase")
	assert.True(transaction.SecondVerify(secondPublicKey))
}
