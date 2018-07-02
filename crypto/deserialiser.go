// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
	// "github.com/davecgh/go-spew/spew"
)

func DeserialiseTransaction(serialised string) *Transaction {
	bytes := HexDecode(serialised)

	transaction := &Transaction{}
	transaction.Serialized = serialised

	assetOffset, transaction := deserialiseHeader(bytes, transaction)
	transaction = deserialiseTypeSpecific(assetOffset, bytes, transaction)
	transaction = deserialiseVersionOne(bytes, transaction)

	// spew.Dump(transaction)

	return transaction
}

////////////////////////////////////////////////////////////////////////////////
// GENERIC DESERIALISING ///////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserialiseHeader(bytes []byte, transaction *Transaction) (int, *Transaction) {
	transaction.Version = ReadInt8(bytes[1:2])
	transaction.Network = ReadInt8(bytes[2:3])
	transaction.Type = ReadInt8(bytes[3:4])
	transaction.Timestamp = ReadInt32(bytes[4:8])
	transaction.SenderPublicKey = HexEncode(bytes[8:41])
	transaction.Fee = ReadInt64(bytes[41:49])

	vendorFieldLength := bytes[49:50][0]

	if vendorFieldLength > 0 {
		vendorFieldOffset := 50 + vendorFieldLength
		transaction.VendorFieldHex = bytes[50:vendorFieldOffset]
	}

	assetOffset := 50*2 + int(vendorFieldLength)*2

	return assetOffset, transaction
}

func deserialiseTypeSpecific(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	transactionType := uint32(transaction.Type)

	switch {
	case transactionType == TRANSACTION_TYPES.Transfer:
		transaction = deserialiseTransfer(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.SecondSignatureRegistration:
		transaction = deserialiseSecondSignatureRegistration(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.DelegateRegistration:
		transaction = deserialiseDelegateRegistration(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.Vote:
		transaction = deserialiseVote(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.MultiSignatureRegistration:
		transaction = deserialiseMultiSignatureRegistration(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.Ipfs:
		transaction = deserialiseIpfs(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.TimelockTransfer:
		transaction = deserialiseTimelockTransfer(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.MultiPayment:
		transaction = deserialiseMultiPayment(assetOffset, bytes, transaction)
	case transactionType == TRANSACTION_TYPES.DelegateResignation:
		transaction = deserialiseDelegateResignation(assetOffset, bytes, transaction)
	}

	return transaction
}

func deserialiseVersionOne(bytes []byte, transaction *Transaction) *Transaction {
	transactionType := uint32(transaction.Type)

	if transaction.SecondSignature != "" {
		transaction.SignSignature = transaction.SecondSignature
	}

	// if transactionType == TRANSACTION_TYPES.Vote {
	//     transaction.RecipientId = PublicKeyFromHex(transaction.SenderPublicKey).Address()
	// }

	// if transactionType == TRANSACTION_TYPES.SecondSignatureRegistration {
	//     transaction.RecipientId = PublicKeyFromHex(transaction.SenderPublicKey).Address()
	// }

	if transactionType == TRANSACTION_TYPES.MultiSignatureRegistration {
		// // The "recipientId" doesn't exist on v1 multi signature registrations
		// // transaction.RecipientId = Address::fromPublicKey($transaction->senderPublicKey);
		// $transaction->asset->multisignature->keysgroup = array_map(function ($key) {
		//     return '+'.$key;
		// }, $transaction->asset->multisignature->keysgroup);
	}

	if len(transaction.VendorFieldHex) > 0 {
		transaction.VendorField = ReadHex(transaction.VendorFieldHex)
	}

	if transaction.Id == "" {
		transaction.Id = transaction.GetId()
	}

	return transaction
}

////////////////////////////////////////////////////////////////////////////////
// TYPE SPECIFICDE SERIALISING /////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserialiseTransfer(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	transaction.Amount = ReadInt64(bytes[offset:(offset + 8)])
	transaction.Expiration = ReadInt32(bytes[(offset + 8):(offset + 16)])

	recipientOffset := offset + 12
	transaction.RecipientId = base58.Encode(bytes[recipientOffset:(recipientOffset + 21)])

	return transaction.ParseSignatures(assetOffset + (21+12)*2)
}

func deserialiseSecondSignatureRegistration(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseDelegateRegistration(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseVote(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseMultiSignatureRegistration(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseIpfs(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseTimelockTransfer(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseMultiPayment(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseDelegateResignation(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}
