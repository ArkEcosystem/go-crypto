// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"errors"

	"encoding/hex"

	blst "github.com/supranational/blst/bindings/go"
)

func buildSignedTransaction(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	transaction.Sign(passphrase)

	if len(secondPassphrase) > 0 {
		transaction.SecondSign(secondPassphrase)
	}

	transaction.Id = transaction.GetId()

	return transaction
}

func buildMultiSignedTransaction(transaction *Transaction, signerIndex int, passphrase string) *Transaction {
	transaction.SignMulti(signerIndex, passphrase)

	transaction.Id = transaction.GetId()

	return transaction
}

func setCommonFields(transaction *Transaction, transactionType uint16) {
	if transaction.Fee == 0 {
		transaction.Fee = GetFee(transactionType)
	}

	if transaction.Network == 0 {
		transaction.Network = GetNetwork().Version
	}

	transaction.SecondSenderPublicKey = ""
	transaction.SecondSignature = ""

	if transaction.Timestamp == 0 {
		transaction.Timestamp = GetTime()
	}

	transaction.Type = transactionType
	transaction.TypeGroup = TRANSACTION_TYPE_GROUPS.Core
	transaction.Version = 1
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
	setCommonFields(transaction, TRANSACTION_TYPES.Transfer)

	transaction.Asset = &TransactionAsset{}

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

/** Set all fields and sign a multi signature TransactionTypes.Transfer transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Amount
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   RecipientId
 *   Signatures - must be an array (could be empty); a new signature will be appended to it
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildTransferMultiSignature(transaction *Transaction, signerIndex int, passphrase string) *Transaction {
	setCommonFields(transaction, TRANSACTION_TYPES.Transfer)

	transaction.Asset = &TransactionAsset{}

	return buildMultiSignedTransaction(transaction, signerIndex, passphrase)
}

/** Set all fields and sign a TransactionTypes.ValidatorRegistration transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Asset.Delegate.Username
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildValidatorRegistration(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction, TRANSACTION_TYPES.ValidatorRegistration)

	if transaction.Asset != nil && transaction.Asset.Validator != nil {
		err := validateBLSPublicKey(transaction.Asset.Validator.ValidatorPublicKey)
		if err != nil {
			panic("Invalid BLS public key: " + err.Error())
		}
	}

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
	setCommonFields(transaction, TRANSACTION_TYPES.Vote)

	transaction.RecipientId, _ = AddressFromPassphrase(passphrase)

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

/** Set all fields and sign a TransactionTypes.MultiSignatureRegistration transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Asset.MultiSignature
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildMultiSignatureRegistration(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction, TRANSACTION_TYPES.MultiSignatureRegistration)

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

/** Set all fields and sign a TransactionTypes.MultiPayment transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Asset.Payments
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildMultiPayment(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction, TRANSACTION_TYPES.MultiPayment)

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}

/** Set all fields and sign a TransactionTypes.ValidatorResignation transaction.
 * Members of the supplied transaction that must be set when calling this function:
 *   Expiration - optional, could be 0 to designate no expiration
 *   Fee - optional, if 0, then it will be set to a default fee
 *   Network - optional, if 0, then it will be set to the configured network
 *   Nonce
 *   Timestamp - optional, if 0, then it will be set to the present time
 *   VendorField - optional */
func BuildValidatorResignation(transaction *Transaction, passphrase string, secondPassphrase string) *Transaction {
	setCommonFields(transaction, TRANSACTION_TYPES.ValidatorResignation)

	return buildSignedTransaction(transaction, passphrase, secondPassphrase)
}


func validateBLSPublicKey(publicKey string) error {
	if len(publicKey) != 96 {
		return errors.New("invalid BLS public key length")
	}

	// Decode the public key from hex
	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return errors.New("invalid BLS public key hex format")
	}

	// Deserialize the public key into a blst.P1Affine structure
	var pubKey blst.P1Affine
	pubKey.Deserialize(pubKeyBytes)

	// Check if the public key is in G1 group and is valid
	if !pubKey.InG1() {
		return errors.New("invalid BLS public key: not in G1 group or invalid structure")
	}

	return nil
}