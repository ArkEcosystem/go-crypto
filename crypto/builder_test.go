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
			Amount: FlexToshi(200000000),
			Expiration: 4333222,
			Fee: FlexToshi(10),
			Network: 30,
			Nonce: 6,
			RecipientId: "DPXaJv1GcVpZPvxw5T4fXebqTVhFpfqyrC",
		},
		"LIq[ChitMOgz66RWvGP1eAY",
		"",
	)
}

func transferWithSecondPassphrase(t *testing.T) *Transaction {
	secondPassPhrase := "This is a top secret second passphrase"

	transaction := BuildTransfer(
		&Transaction{
			Amount: FlexToshi(133380000000),
			Nonce: 5,
			RecipientId: "AXoXnFi4z1Z6aFvjEYkDVCtBGW2PaRiM25",
			VendorField: "This is a transaction from Go",
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
		Amount: FlexToshi(200000000),
		Expiration: 4333222,
		Fee: FlexToshi(10),
		Network: 30,
		Nonce: 6,
		RecipientId: "DPXaJv1GcVpZPvxw5T4fXebqTVhFpfqyrC",
	}

	transaction = BuildTransferMultiSignature(transaction, 0, "multisig participant 1")
	transaction = BuildTransferMultiSignature(transaction, 1, "multisig participant 2")

	return transaction
}

func secondSignatureRegistration(t *testing.T) *Transaction {
	return BuildSecondSignatureRegistration(
		&Transaction{
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"This is a top secret second passphrase",
	)
}

func delegateRegistrationWithPassphrase(t *testing.T) *Transaction {
	return BuildDelegateRegistration(
		&Transaction{
			Asset: &TransactionAsset{
				Delegate: &DelegateAsset{
					Username: "polopolo",
				},
			},
			Nonce: 5,
		},
		"lumber desk thought industry island man slow vendor pact fragile enact season",
		"",
	)
}

func delegateRegistrationWithSecondPassphrase(t *testing.T) *Transaction {
	secondPassPhrase := "This is a top secret second passphrase"

	transaction := BuildDelegateRegistration(
		&Transaction{
			Asset: &TransactionAsset{
				Delegate: &DelegateAsset{
					Username: "polopolo",
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
				Votes: []string{ "+034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192" },
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
				Votes: []string{ "+034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192" },
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

func ipfsWithPassphrase(t *testing.T) *Transaction {
	return BuildIpfs(
		&Transaction{
			Asset: &TransactionAsset{
				Ipfs: "QmYSK2JyM3RyDyB52caZCTKFR3HKniEcMnNJYdk8DQ6KKB",
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
					{ Amount: FlexToshi(111222), RecipientId: "DHKxXag9PjfjHBbPg3HQS5WCaQZdgDf6yi" },
					{ Amount: FlexToshi(222333), RecipientId: "DBzGiUk8UVjB2dKCfGRixknB7Ki3Zhqthp" },
					{ Amount: FlexToshi(333444), RecipientId: "DFa7vn1LvWAyTuVDrQUr5NKaM73cfjx2Cp" },
				},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func delegateResignationWithPassphrase(t *testing.T) *Transaction {
	return BuildDelegateResignation(
		&Transaction{
			Amount: FlexToshi(0),
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func htlcLockWithPassphrase(t *testing.T) *Transaction {
	return BuildHtlcLock(
		&Transaction{
			Asset: &TransactionAsset{
				Lock: &HtlcLockAsset{
					SecretHash: "ca270216d522f0aa774edea7ad3c7440e8214f2625da0edbc948b28a0d3f5ead",
					Expiration: &HtlcLockExpirationAsset{
						Type: 2,
						Value: 111222333,
					},
				},
			},
			Nonce: 5,
			RecipientId: "DPXaJv1GcVpZPvxw5T4fXebqTVhFpfqyrC",
		},
		"This is a top secret passphrase",
		"",
	)
}

func htlcClaimWithPassphrase(t *testing.T) *Transaction {
	return BuildHtlcClaim(
		&Transaction{
			Asset: &TransactionAsset{
				Claim: &HtlcClaimAsset{
					LockTransactionId: "d25c84e544bafc1d1bed9538c67b4275b0b79f49ef6b8677b31a709650442fe9",
					UnlockSecret: "7a5d646b6d604e466e6e395554767431606c5d434a5b466f68635261714e685a",
				},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func htlcRefundWithPassphrase(t *testing.T) *Transaction {
	return BuildHtlcRefund(
		&Transaction{
			Asset: &TransactionAsset{
				Refund: &HtlcRefundAsset{
					LockTransactionId: "d25c84e544bafc1d1bed9538c67b4275b0b79f49ef6b8677b31a709650442fe9",
				},
			},
			Nonce: 5,
		},
		"This is a top secret passphrase",
		"",
	)
}

func TestBuild(t *testing.T) {
	for builderName, buildTransaction := range map[string]func(*testing.T) *Transaction{
		"TransferWithPassphrase": transferWithPassphrase,
		"TransferWithSecondPassphrase": transferWithSecondPassphrase,
		"SecondSignatureRegistration": secondSignatureRegistration,
		"DelegateRegistrationWithPassphrase": delegateRegistrationWithPassphrase,
		"DelegateRegistrationWithSecondPassphrase": delegateRegistrationWithSecondPassphrase,
		"VoteWithPassphrase": voteWithPassphrase,
		"VoteWithSecondPassphrase": voteWithSecondPassphrase,
		"MultiSignatureRegistrationWithPassphrase": multiSignatureRegistrationWithPassphrase,
		"IpfsWithPassphrase": ipfsWithPassphrase,
		"MultiPaymentWithPassphrase": multiPaymentWithPassphrase,
		"DelegateResignationWithPassphrase": delegateResignationWithPassphrase,
		"HtlcLockWithPassphrase": htlcLockWithPassphrase,
		"HtlcClaimWithPassphrase": htlcClaimWithPassphrase,
		"HtlcRefundWithPassphrase": htlcRefundWithPassphrase,
	} {
		for signatureTypeString, signatureType := range map[string]int{
			"ECDSA": SIGNATURE_TYPE_ECDSA,
			"Schnorr": SIGNATURE_TYPE_SCHNORR,
		} {
			CONFIG_SIGNATURE_TYPE = signatureType

			test := func (t *testing.T) {
				transaction := buildTransaction(t)

				assert := assert.New(t)

				assert.True(transaction.Verify())
			}

			t.Run(fmt.Sprintf("%s-%s", builderName, signatureTypeString), test)
		}
	}

	// Test multisignature transfer separately

	CONFIG_SIGNATURE_TYPE = SIGNATURE_TYPE_SCHNORR

	test := func (t *testing.T) {
		transaction := transferMultiSignature(t)

		assert := assert.New(t)

		multiSignatureAsset := &MultiSignatureRegistrationAsset{
			Min: 2,
			PublicKeys: []string{
				"037eaa8cb236c40a08fcb9d6220743ee6ae1b5c40e8a77a38f286516c3ff663901",
				"0301fd417566397113ba8c55de2f093a572744ed1829b37b56a129058000ef7bce",
				"0209d3c0f68994253cee24b23df3266ba1f0ca2f0666cd69a46544d63001cdf150",
			},
		}

		assert.True(transaction.Verify(multiSignatureAsset))
	}

	t.Run("TransferMultiSignature-Schnorr", test)
}

