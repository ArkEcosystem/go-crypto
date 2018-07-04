// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package arkecosystem_crypto

func createSignedTransaction(transaction *Transaction, secret string, secondSecret string) *Transaction {
	transaction.Timestamp = GetTime()
	transaction.Sign(secret)

	if len(secondSecret) > 0 {
		transaction.SecondSign(secondSecret)
	}

	transaction.Id = transaction.GetId()

	return transaction
}

func BuildTransfer(recipient string, amount uint64, vendorField string, secret string, secondSecret string) *Transaction {
	transaction := &Transaction{
		Type:        TRANSACTION_TYPES.Transfer,
		Fee:         TRANSACTION_FEES.Transfer,
		RecipientId: recipient,
		Amount:      amount,
		VendorField: vendorField,
		Asset:       &TransactionAsset{},
	}

	return createSignedTransaction(transaction, secret, secondSecret)
}

func BuildSecondSignatureRegistration(secret string, secondSecret string) *Transaction {
	transaction := &Transaction{
		Type:  TRANSACTION_TYPES.SecondSignatureRegistration,
		Fee:   TRANSACTION_FEES.SecondSignatureRegistration,
		Asset: &TransactionAsset{},
	}

	publicKey, _ := PublicKeyFromSecret(secret)

	transaction.Asset.Signature = &SecondSignatureRegistrationAsset{
		PublicKey: HexEncode(publicKey.Serialize()),
	}

	return createSignedTransaction(transaction, secret, secondSecret)
}

func BuildDelegateRegistration(username string, secret string, secondSecret string) *Transaction {
	transaction := &Transaction{
		Type:  TRANSACTION_TYPES.DelegateRegistration,
		Fee:   TRANSACTION_FEES.DelegateRegistration,
		Asset: &TransactionAsset{},
	}

	transaction.Asset.Delegate = &DelegateAsset{
		Username: username,
	}

	return createSignedTransaction(transaction, secret, secondSecret)
}

func BuildVote(vote, secret, secondSecret string) *Transaction {
	transaction := &Transaction{
		Type:  TRANSACTION_TYPES.Vote,
		Fee:   TRANSACTION_FEES.Vote,
		Asset: &TransactionAsset{},
	}

	transaction.RecipientId, _ = AddressFromSecret(secret)
	transaction.Asset.Votes = append(transaction.Asset.Votes, vote)

	return createSignedTransaction(transaction, secret, secondSecret)
}

// func BuildMultiSignatureRegistration() *Transaction {}
