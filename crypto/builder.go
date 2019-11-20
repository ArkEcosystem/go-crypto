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
	transaction.Asset = &TransactionAsset{}

	if transaction.Fee == 0 {
		transaction.Fee = GetFee(TRANSACTION_TYPES.Transfer)
	}

	if transaction.Network == 0 {
		transaction.Network = GetNetwork().Version
	}

	transaction.SecondSenderPublicKey = ""
	transaction.SecondSignature = ""
	transaction.Signatures = nil
	transaction.Type = TRANSACTION_TYPES.Transfer
	transaction.TypeGroup = TRANSACTION_TYPE_GROUPS.Core
	transaction.Version = 2

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildSecondSignatureRegistration(passphrase string, secondPassphrase string) *Transaction {
	transaction := &Transaction{
		Type: TRANSACTION_TYPES.SecondSignatureRegistration,
		TypeGroup: TRANSACTION_TYPE_GROUPS.Core,
		Fee: GetFee(TRANSACTION_TYPES.SecondSignatureRegistration),
		Asset: &TransactionAsset{},
	}

	publicKey, _ := PublicKeyFromPassphrase(passphrase)

	transaction.Asset.Signature = &SecondSignatureRegistrationAsset{
		PublicKey: HexEncode(publicKey.Serialize()),
	}

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildDelegateRegistration(username string, passphrase string, secondPassphrase string) *Transaction {
	transaction := &Transaction{
		Type: TRANSACTION_TYPES.DelegateRegistration,
		TypeGroup: TRANSACTION_TYPE_GROUPS.Core,
		Fee: GetFee(TRANSACTION_TYPES.DelegateRegistration),
		Asset: &TransactionAsset{},
	}

	transaction.Asset.Delegate = &DelegateAsset{
		Username: username,
	}

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

func BuildVote(vote, passphrase string, secondPassphrase string) *Transaction {
	transaction := &Transaction{
		Type: TRANSACTION_TYPES.Vote,
		TypeGroup: TRANSACTION_TYPE_GROUPS.Core,
		Fee: GetFee(TRANSACTION_TYPES.Vote),
		Asset: &TransactionAsset{},
	}

	transaction.RecipientId, _ = AddressFromPassphrase(passphrase)
	transaction.Asset.Votes = append(transaction.Asset.Votes, vote)

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
