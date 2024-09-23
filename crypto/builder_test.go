// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func transferWithPassphrase(t *testing.T) *Transaction {
	return BuildTransfer(
		&Transaction{
			Amount:      FlexToshi(133380000000),
			Expiration:  4333222,
			Fee:         FlexToshi(10),
			Network:     30,
			Nonce:       6,
			RecipientId: "0xb0FF9213f7226bBB72b84dE16af86e56f1f38B01",
		},
		"my super secret passphrase",
		"",
	)
}

func transferWithSecondPassphrase(t *testing.T) *Transaction {
	secondPassPhrase := "This is a top secret second passphrase"

	transaction := BuildTransfer(
		&Transaction{
			Amount:       FlexToshi(133380000000),
			Nonce:        5,
			RecipientId:  "0xb0FF9213f7226bBB72b84dE16af86e56f1f38B01",
			VendorField:  "This is a transaction from Go",
		},
		"This is a top secret passphrase",
		secondPassPhrase,
	)

	assert := assert.New(t)

	secondPublicKey, _ := PublicKeyFromPassphrase(secondPassPhrase)
	assert.True(transaction.SecondVerify(secondPublicKey))

	return transaction
}

func transferMultiSignature(t *testing.T) *Transaction {
	transaction := &Transaction{
		Amount:       FlexToshi(200000000),
		Expiration:   4333222,
		Fee:          FlexToshi(10),
		Network:      30,
		Nonce:        6,
		RecipientId:  "0xb693449AdDa7EFc015D87944EAE8b7C37EB1690A",
	}

	transaction = BuildTransferMultiSignature(transaction, 0, "multisig participant 1")
	transaction = BuildTransferMultiSignature(transaction, 1, "multisig participant 2")

	return transaction
}

func validatorRegistrationWithPassphrase(t *testing.T) *Transaction {
	return BuildValidatorRegistration(
		&Transaction{
			Asset: &TransactionAsset{
				Validator: &ValidatorAsset{
					ValidatorPublicKey: "a08058db53e2665c84a40f5152e76dd2b652125a6079130d4c315e728bcf4dd1dfb44ac26e82302331d61977d3141118",
				},
			},
			Nonce: 5,
		},
		"lumber desk thought industry island man slow vendor pact fragile enact season",
		"",
	)
}

func validatorRegistrationWithSecondPassphrase(t *testing.T) *Transaction {
	secondPassPhrase := "This is a top secret second passphrase"

	transaction := BuildValidatorRegistration(
		&Transaction{
			Asset: &TransactionAsset{
				Validator: &ValidatorAsset{
					ValidatorPublicKey: "a08058db53e2665c84a40f5152e76dd2b652125a6079130d4c315e728bcf4dd1dfb44ac26e82302331d61977d3141118",
				},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		secondPassPhrase,
	)

	assert := assert.New(t)

	secondPublicKey, _ := PublicKeyFromPassphrase(secondPassPhrase)
	assert.True(transaction.SecondVerify(secondPublicKey))

	return transaction
}

func voteWithPassphrase(t *testing.T) *Transaction {
	return BuildVote(
		&Transaction{
			Asset: &TransactionAsset{
				Votes: []string{"034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func voteWithSecondPassphrase(t *testing.T) *Transaction {
	secondPassPhrase := "This is a top secret second passphrase"

	transaction := BuildVote(
		&Transaction{
			Asset: &TransactionAsset{
				Votes: []string{"034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192"},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		secondPassPhrase,
	)

	assert := assert.New(t)

	secondPublicKey, _ := PublicKeyFromPassphrase(secondPassPhrase)
	assert.True(transaction.SecondVerify(secondPublicKey))

	return transaction
}

func unvoteVoteWithPassphrase(t *testing.T) *Transaction {
	return BuildVote(
		&Transaction{
			Asset: &TransactionAsset{
				Votes: []string{
					"034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed193",
				},
				Unvotes: []string{
					"034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192",
				},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func multiSignatureRegistrationWithPassphrase(t *testing.T) *Transaction {
	return BuildMultiSignatureRegistration(
		&Transaction{
			Asset: &TransactionAsset{
				MultiSignature: &MultiSignatureRegistrationAsset{
					Min: 2,
					PublicKeys: []string{
						"03a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933",
						"03b02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933",
						"03c02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933",
					},
				},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func multiPaymentWithPassphrase(t *testing.T) *Transaction {
	return BuildMultiPayment(
		&Transaction{
			Asset: &TransactionAsset{
				Payments: []*MultiPaymentAsset{
					{Amount: FlexToshi(111222), RecipientId: "0xb0FF9213f7226bBB72b84dE16af86e56f1f38B01"},
					{Amount: FlexToshi(222333), RecipientId: "0xb693449AdDa7EFc015D87944EAE8b7C37EB1690A"},
					{Amount: FlexToshi(333444), RecipientId: "0xb0FF9213f7226bBB72b84dE16af86e56f1f38B01"},
				},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func validatorResignationWithPassphrase(t *testing.T) *Transaction {
	return BuildValidatorResignation(
		&Transaction{
			Amount:  FlexToshi(0),
			Nonce:   5,
		},
		"This is a top secret passphrase",
		"",
	)
}


func TestBuild(t *testing.T) {
	for builderName, buildTransaction := range map[string]func(*testing.T) *Transaction{
		"TransferWithPassphrase":                  transferWithPassphrase,
		"TransferWithSecondPassphrase":            transferWithSecondPassphrase,
		"ValidatorRegistrationWithPassphrase":     validatorRegistrationWithPassphrase,
		"ValidatorRegistrationWithSecondPassphrase": validatorRegistrationWithSecondPassphrase,
		"VoteWithPassphrase":                      voteWithPassphrase,
		"VoteWithSecondPassphrase":                voteWithSecondPassphrase,
		"UnvoteVoteWithPassphrase":                unvoteVoteWithPassphrase,
		"MultiSignatureRegistrationWithPassphrase": multiSignatureRegistrationWithPassphrase,
		"MultiPaymentWithPassphrase":              multiPaymentWithPassphrase,
		"ValidatorResignationWithPassphrase":      validatorResignationWithPassphrase,
	} {
		// Iterate only over Schnorr signature type
		for signatureTypeString, signatureType := range map[string]int{
			"Schnorr": SIGNATURE_TYPE_SCHNORR,
		} {
			CONFIG_SIGNATURE_TYPE = signatureType

			test := func(t *testing.T) {
				transaction := buildTransaction(t)
				
				assert := assert.New(t)

				assert.True(transaction.Verify())
			}

			t.Run(fmt.Sprintf("%s-%s", builderName, signatureTypeString), test)
		}
	}

	// Test multisignature transfer separately
	test := func(t *testing.T) {
		transaction := transferMultiSignature(t)

		assert := assert.New(t)

		multiSignatureAsset := &MultiSignatureRegistrationAsset{
			Min: 2,
			PublicKeys: []string{
				"037eaa8cb236c40a08fcb9d6220743ee6ae1b5c40e8a77a38f286516c3ff663901",
				"0301fd417566397113ba8c55de2f093a572744ed1829b37b56a129058000ef7bce",
			},
		}

		assert.True(transaction.Verify(multiSignatureAsset))
	}

	t.Run("TransferMultiSignature-Schnorr", test)
}


func TestBuildValidatorRegistrationWithInvalidKeyLength(t *testing.T) {
	assert.PanicsWithValue(t, "Invalid BLS public key: invalid BLS public key length", func() {
		BuildValidatorRegistration(
			&Transaction{
				Asset: &TransactionAsset{
					Validator: &ValidatorAsset{
						// ValidatorPublicKey: "b08058db53e2665c84a40f5152e76dd2b652125a6079130d4c315e728bcf4dd1dfb44ac26e82302331d61977d3141118",
						ValidatorPublicKey: "b08058db53e2665c84a40f5152e76dd2b65212",
					},
				},
				Nonce: 5,
			},
			"lumber desk thought industry island man slow vendor pact fragile enact season",
			"",
		)
	})
}

func TestBuildValidatorRegistrationWithInvalidKey(t *testing.T) {
	assert.PanicsWithValue(t, "Invalid BLS public key: invalid BLS public key hex format", func() {
		BuildValidatorRegistration(
			&Transaction{
				Asset: &TransactionAsset{
					Validator: &ValidatorAsset{
						ValidatorPublicKey: "j08058db53e2665c84a40f5152e76dd2b652125a6079130d4c315e728bcf4dd1dfb44ac26e82302331d61977d3141118",
					},
				},
				Nonce: 5,
			},
			"lumber desk thought industry island man slow vendor pact fragile enact season",
			"",
		)
	})
}