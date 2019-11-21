// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/binary"
	"fmt"
	"log"

	b58 "github.com/btcsuite/btcutil/base58"
)

var compactPubKeyLen = 33 // bytes

func DeserializeTransaction(serialized string) *Transaction {
	transaction := &Transaction{}
	transaction.Serialized = HexDecode(serialized)

	typeSpecificOffset := deserializeHeader(transaction)
	transaction = deserializeTypeSpecific(typeSpecificOffset, transaction)
	transaction = deserializeCommon(transaction)

	return transaction
}

////////////////////////////////////////////////////////////////////////////////
// GENERIC DESERIALISING ///////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserializeHeader(transaction *Transaction) int {
	transaction.Version = transaction.Serialized[1:2][0]
	transaction.Network = transaction.Serialized[2:3][0]
	transaction.TypeGroup = binary.LittleEndian.Uint32(transaction.Serialized[3:7])
	transaction.Type = binary.LittleEndian.Uint16(transaction.Serialized[7:9])
	transaction.Nonce = binary.LittleEndian.Uint64(transaction.Serialized[9:17])
	transaction.SenderPublicKey = HexEncode(transaction.Serialized[17:50])
	transaction.Fee = FlexToshi(binary.LittleEndian.Uint64(transaction.Serialized[50:58]))

	vendorFieldLength := transaction.Serialized[58:59][0]

	if vendorFieldLength > 0 {
		transaction.VendorField = string(transaction.Serialized[59:59 + vendorFieldLength])
	}

	typeSpecificOffset := int(59 + vendorFieldLength)

	return typeSpecificOffset
}

func deserializeTypeSpecific(typeSpecificOffset int, transaction *Transaction) *Transaction {
	switch transaction.Type {
	case TRANSACTION_TYPES.Transfer:
		transaction = deserializeTransfer(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.SecondSignatureRegistration:
		transaction = deserializeSecondSignatureRegistration(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.DelegateRegistration:
		transaction = deserializeDelegateRegistration(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.Vote:
		transaction = deserializeVote(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.MultiSignatureRegistration:
		transaction = deserializeMultiSignatureRegistration(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.Ipfs:
		transaction = deserializeIpfs(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.MultiPayment:
		transaction = deserializeMultiPayment(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.DelegateResignation:
		transaction = deserializeDelegateResignation(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.HtlcLock:
		transaction = deserializeHtlcLock(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.HtlcClaim:
		transaction = deserializeHtlcClaim(typeSpecificOffset, transaction)
	case TRANSACTION_TYPES.HtlcRefund:
		transaction = deserializeHtlcRefund(typeSpecificOffset, transaction)
	}

	return transaction
}

func deserializeCommon(transaction *Transaction) *Transaction {
	if transaction.Type == TRANSACTION_TYPES.Vote ||
		transaction.Type == TRANSACTION_TYPES.SecondSignatureRegistration ||
		transaction.Type == TRANSACTION_TYPES.MultiSignatureRegistration {

		publicKey, _ := PublicKeyFromHex(transaction.SenderPublicKey)
		publicKey.Network.Version = transaction.Network

		transaction.RecipientId = publicKey.ToAddress()
	}

	if transaction.Id == "" {
		transaction.Id = transaction.GetId()
	}

	return transaction
}

////////////////////////////////////////////////////////////////////////////////
// TYPE SPECIFIC DESERIALISING /////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserializeTransfer(typeSpecificOffset int, transaction *Transaction) *Transaction {
	o := typeSpecificOffset

	transaction.Amount = FlexToshi(binary.LittleEndian.Uint64(transaction.Serialized[o:o + 8]))
	o += 8

	transaction.Expiration = binary.LittleEndian.Uint32(transaction.Serialized[o:o + 4])
	o += 4

	recipientVersion := transaction.Serialized[o]
	o++

	recipientRaw := transaction.Serialized[o:o + 20]
	o += 20

	transaction.RecipientId = b58.CheckEncode(recipientRaw, recipientVersion)

	return transaction.ParseSignatures(o)
}

func deserializeSecondSignatureRegistration(typeSpecificOffset int, transaction *Transaction) *Transaction {
	transaction.Asset = &TransactionAsset{
		Signature: &SecondSignatureRegistrationAsset{
			PublicKey: HexEncode(transaction.Serialized[typeSpecificOffset:typeSpecificOffset + compactPubKeyLen]),
		},
	}

	return transaction.ParseSignatures(typeSpecificOffset + compactPubKeyLen)
}

func deserializeDelegateRegistration(typeSpecificOffset int, transaction *Transaction) *Transaction {
	o := typeSpecificOffset

	usernameLen := int(transaction.Serialized[o])
	o++

	transaction.Asset = &TransactionAsset{
		Delegate: &DelegateAsset{
			Username: string(transaction.Serialized[o:o + usernameLen]),
		},
	}
	o += usernameLen

	return transaction.ParseSignatures(o)
}

func deserializeVote(typeSpecificOffset int, transaction *Transaction) *Transaction {
	o := typeSpecificOffset

	numVotes := int(transaction.Serialized[o])
	o++

	transaction.Asset = &TransactionAsset{}

	for i := 0; i < numVotes; i++ {
		// 0 = unvote (-), 1 = vote (+)
		voteType := transaction.Serialized[o]
		o++

		delegatePublicKeyHex := HexEncode(transaction.Serialized[o:o + compactPubKeyLen])
		o += compactPubKeyLen

		pfx := "+"
		if voteType == 0 {
			pfx = "-"
		}

		transaction.Asset.Votes = append(transaction.Asset.Votes, fmt.Sprintf("%s%s", pfx, delegatePublicKeyHex))
	}

	return transaction.ParseSignatures(o)
}

func deserializeMultiSignatureRegistration(assetOffset int, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	transaction.Asset = &TransactionAsset{}
	transaction.Asset.MultiSignature = &MultiSignatureRegistrationAsset{}

	transaction.Asset.MultiSignature.Min = transaction.Serialized[offset]

	count := int(transaction.Serialized[offset+1])
	for i := 0; i < count; i++ {
		offsetStart := assetOffset + 4 + i*66
		offsetEnd := assetOffset + 4 + (i+1)*66

		keyHex := HexEncode(transaction.Serialized[offsetStart:offsetEnd])

		transaction.Asset.MultiSignature.PublicKeys = append(transaction.Asset.MultiSignature.PublicKeys, keyHex)
	}

	return transaction.ParseSignatures(assetOffset + 6 + count*66)
}

func deserializeIpfs(typeSpecificOffset int, transaction *Transaction) *Transaction {
	// ipfs hash:
	// transaction.Serialized[offset + 0] - function
	// transaction.Serialized[offset + 1] - length (L)
	// transaction.Serialized[offset + 2 : offset + 2 + L] - data

	o := typeSpecificOffset

	length := int(transaction.Serialized[o + 1])

	ipfsHash := transaction.Serialized[o:o + 2 + length]
	o += 2 + length

	transaction.Asset = &TransactionAsset{
		Ipfs: b58.Encode(ipfsHash),
	}

	return transaction.ParseSignatures(o)
}

func deserializeMultiPayment(assetOffset int, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	total := int(binary.LittleEndian.Uint16(transaction.Serialized[offset:(offset + 4)]))
	offset = assetOffset/2 + 1

	transaction.Asset = &TransactionAsset{}

	for i := 0; i < total; i++ {
		payment := &MultiPaymentAsset{}
		payment.Amount = FlexToshi(binary.LittleEndian.Uint64(transaction.Serialized[offset:(offset + 8)]))
		recipientOffset := offset + 1
		payment.RecipientId = b58.CheckEncode(transaction.Serialized[recipientOffset + 1 : recipientOffset + 20], transaction.Serialized[recipientOffset])

		transaction.Asset.Payments = append(transaction.Asset.Payments, payment)

		offset += 22
	}

	for i := 0; i < len(transaction.Asset.Payments); i++ {
		transaction.Amount += transaction.Asset.Payments[i].Amount
	}

	return transaction.ParseSignatures(offset * 2)
}

func deserializeDelegateResignation(assetOffset int, transaction *Transaction) *Transaction {
	log.Fatal("not implemented deserializeDelegateResignation()")
	return transaction
}

func deserializeHtlcLock(assetOffset int, transaction *Transaction) *Transaction {
	log.Fatal("not implemented deserializeHtlcLock()")
	return transaction
}

func deserializeHtlcClaim(assetOffset int, transaction *Transaction) *Transaction {
	log.Fatal("not implemented deserializeHtlcClaim()")
	return transaction
}

func deserializeHtlcRefund(assetOffset int, transaction *Transaction) *Transaction {
	log.Fatal("not implemented deserializeHtlcRefund()")
	return transaction
}
