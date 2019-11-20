// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"log"
)

func buildSignedTransaction(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	if transaction.Timestamp == 0 {
		transaction.Timestamp = GetTime()
	}

	transaction.Sign(passphrase)

	if len(secondPassphrase) > 0 {
		transaction.SecondSign(secondPassphrase)
	}

	transaction.Id = transaction.GetId()

	return transaction
}

func setCommonFields(transaction *Transaction) {
	if transaction.Fee == 0 {
		transaction.Fee = GetFee(TRANSACTION_TYPES.Transfer)
	}

	if transaction.Network == 0 {
		transaction.Network = GetNetwork().Version
	}

	transaction.SecondSenderPublicKey = ""
	transaction.SecondSignature = ""
	transaction.Signatures = nil
	transaction.TypeGroup = TRANSACTION_TYPE_GROUPS.Core
	transaction.Version = 2
}

/** Set all fields and sign a TransactionTypes.Transfer transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Amount
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   RecipientId
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildTransfer(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction)

	transaction.Asset = &TransactionAsset{}
	transaction.Type = TRANSACTION_TYPES.Transfer

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

/** Set all fields and sign a TransactionTypes.SecondSignatureRegistration transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildSecondSignatureRegistration(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction)

	secondPublicKey, _ := PublicKeyFromPassphrase(secondPassphrase)

	transaction.Amount = 0
	transaction.Asset = &TransactionAsset{
		Signature: &SecondSignatureRegistrationAsset{
			PublicKey: HexEncode(secondPublicKey.Serialize()),
		},
	}

	transaction.Type = TRANSACTION_TYPES.SecondSignatureRegistration

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

/** Set all fields and sign a TransactionTypes.DelegateRegistration transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Asset.Delegate.Username
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildDelegateRegistration(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction)

	transaction.Type = TRANSACTION_TYPES.DelegateRegistration

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

/** Set all fields and sign a TransactionTypes.Vote transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Asset.Votes
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildVote(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction)

	transaction.RecipientId, _ = AddressFromPassphrase(passphrase)
	transaction.Type = TRANSACTION_TYPES.Vote

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildMultiSignatureRegistration(min byte, lifetime byte, publickeys []string, passphrase string, secondPassphrase string) *Transaction {
	transaction := &Transaction{
		Type: TRANSACTION_TYPES.MultiSignatureRegistration,
		TypeGroup: TRANSACTION_TYPE_GROUPS.Core,
		Asset: &TransactionAsset{},
	}

	transaction.Asset.MultiSignature = &MultiSignatureRegistrationAsset{
		Min: min,
		PublicKeys: publickeys,
	}

	transaction.Fee = FlexToshi(len(publickeys)+1) + GetFee(TRANSACTION_TYPES.MultiSignatureRegistration)

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildIpfs(amount FlexToshi, ipfsId string, passphrase string, secondPassphrase string) *Transaction {
	transaction := &Transaction{
		Type: TRANSACTION_TYPES.Transfer,
		TypeGroup: TRANSACTION_TYPE_GROUPS.Core,
		Fee: GetFee(TRANSACTION_TYPES.Transfer),
		Amount: amount,
		Asset: &TransactionAsset{
			Ipfs: ipfsId,
		},
	}

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildMultiPayment(passphrase string, secondPassphrase string) *Transaction {
	log.Fatal("Not implemented: BuildMultiPayment()")
	transaction := &Transaction{}
	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildDelegateResignation(passphrase string, secondPassphrase string) *Transaction {
	log.Fatal("Not implemented: BuildDelegateResignation()")
	transaction := &Transaction{}
	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildHtlcLock(passphrase string, secondPassphrase string) *Transaction {
	log.Fatal("Not implemented: BuildHtlcLock()")
	transaction := &Transaction{}
	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildHtlcClaim(passphrase string, secondPassphrase string) *Transaction {
	log.Fatal("Not implemented: BuildHtlcClaim()")
	transaction := &Transaction{}
	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildHtlcRefund(passphrase string, secondPassphrase string) *Transaction {
	log.Fatal("Not implemented: BuildHtlcRefund()")
	transaction := &Transaction{}
	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}
