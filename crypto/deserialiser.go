// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
	"github.com/davecgh/go-spew/spew"
	"strconv"
)

func DeserialiseTransaction(serialised string) {
	bytes := HexDecode(serialised)

	model := &Transaction{}
	model.Serialized = serialised

	assetOffset, model := deserialiseHeader(bytes, model)
	model = deserialiseTransfer(assetOffset, bytes, model)
	// deserialiseTypeSpecific(transaction)
	// deserialiseVersionOne(transaction)

	spew.Dump(model)
}

////////////////////////////////////////////////////////////////////////////////
// GENERIC DESERIALISING ///////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserialiseHeader(bytes []byte, transaction *Transaction) (int, *Transaction) {
	transaction.Version, _ = strconv.Atoi(ReadInt8(bytes[1:2]))
	transaction.Network = ReadInt8(bytes[2:3])
	transaction.Type, _ = strconv.Atoi(ReadInt8(bytes[3:4]))
	transaction.Timestamp = ReadInt32(bytes[4:8])
	transaction.SenderPublicKey = HexEncode(bytes[8:41])
	transaction.Fee = ReadInt64(bytes[41:49])

	vendorFieldLength, _ := strconv.Atoi(ReadInt8(bytes[49:50]))
	if vendorFieldLength > 0 {
		vendorFieldOffset := 50 + vendorFieldLength
		transaction.VendorField = ReadHex(bytes[50:vendorFieldOffset])
	}

	assetOffset := 50*2 + vendorFieldLength*2

	return assetOffset, transaction
}

func deserialiseTypeSpecific(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseVersionOne(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

////////////////////////////////////////////////////////////////////////////////
// TYPE SPECIFICDE SERIALISING /////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserialiseDelegateRegistration(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseDelegateResignation(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseIpfs(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseMultiPayment(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseMultiSignatureRegistration(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseSecondSignatureRegistration(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseTimelockTransfer(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}

func deserialiseTransfer(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	transaction.Amount = ReadInt64(bytes[offset:(offset + 8)])
	transaction.Expiration = ReadInt32(bytes[(offset + 8):(offset + 16)])
	transaction.RecipientId = base58.Encode(bytes[64:85])

	return ParseSignatures(transaction, assetOffset + (21+12)*2)
}

func deserialiseVote(bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}
