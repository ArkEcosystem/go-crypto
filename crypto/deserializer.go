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
	"strconv"

	"github.com/ArkEcosystem/go-crypto/crypto/base58"
)

func DeserializeTransaction(serialized string) *Transaction {
	bytes := HexDecode(serialized)

	transaction := &Transaction{}
	transaction.Serialized = serialized

	assetOffset, transaction := deserializeHeader(bytes, transaction)
	transaction = deserializeTypeSpecific(assetOffset, bytes, transaction)
	transaction = deserializeVersionOne(bytes, transaction)

	return transaction
}

////////////////////////////////////////////////////////////////////////////////
// GENERIC DESERIALISING ///////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserializeHeader(bytes []byte, transaction *Transaction) (int, *Transaction) {
	transaction.Version = bytes[1:2][0]
	transaction.Network = bytes[2:3][0]
	transaction.Type = bytes[3:4][0]
	transaction.Timestamp = int32(binary.LittleEndian.Uint32(bytes[4:8]))
	transaction.SenderPublicKey = HexEncode(bytes[8:41])
	transaction.Fee = FlexToshi(binary.LittleEndian.Uint64(bytes[41:49]))

	vendorFieldLength := bytes[49:50][0]

	if vendorFieldLength > 0 {
		vendorFieldOffset := 50 + vendorFieldLength
		transaction.VendorFieldHex = Hex2Byte(bytes[50:vendorFieldOffset])
	}

	assetOffset := 50*2 + int(vendorFieldLength)*2

	return assetOffset, transaction
}

func deserializeTypeSpecific(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	switch {
	case transaction.Type == TRANSACTION_TYPES.Transfer:
		transaction = deserializeTransfer(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.SecondSignatureRegistration:
		transaction = deserializeSecondSignatureRegistration(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.DelegateRegistration:
		transaction = deserializeDelegateRegistration(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.Vote:
		transaction = deserializeVote(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.MultiSignatureRegistration:
		transaction = deserializeMultiSignatureRegistration(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.Ipfs:
		transaction = deserializeIpfs(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.TimelockTransfer:
		transaction = deserializeTimelockTransfer(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.MultiPayment:
		transaction = deserializeMultiPayment(assetOffset, bytes, transaction)
	case transaction.Type == TRANSACTION_TYPES.DelegateResignation:
		transaction = deserializeDelegateResignation(assetOffset, bytes, transaction)
	}

	return transaction
}

func deserializeVersionOne(bytes []byte, transaction *Transaction) *Transaction {
	if transaction.SecondSignature != "" {
		transaction.SignSignature = transaction.SecondSignature
	}

	if transaction.Type == TRANSACTION_TYPES.Vote {
		publicKey, _ := PublicKeyFromHex(transaction.SenderPublicKey)
		publicKey.Network.Version = transaction.Network

		transaction.RecipientId = publicKey.ToAddress()
	}

	if transaction.Type == TRANSACTION_TYPES.MultiSignatureRegistration {
		keysgroup := make([]string, 0)

		for _, element := range transaction.Asset.MultiSignature.Keysgroup {
			if element[:1] == "+" {
				keysgroup = append(keysgroup, element)
			} else {
				keysgroup = append(keysgroup, fmt.Sprintf("%s%s", "+", element))
			}
		}

		transaction.Asset.MultiSignature.Keysgroup = keysgroup
	}

	if len(transaction.VendorFieldHex) > 0 {
		transaction.VendorField = string(HexDecode(transaction.VendorFieldHex))
	}

	if transaction.Type == TRANSACTION_TYPES.SecondSignatureRegistration || transaction.Type == TRANSACTION_TYPES.MultiSignatureRegistration {
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
// TYPE SPECIFICDE SERIALISING /////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func deserializeTransfer(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	transaction.Amount = FlexToshi(binary.LittleEndian.Uint64(bytes[offset:(offset + 8)]))
	transaction.Expiration = binary.LittleEndian.Uint32(bytes[(offset + 8):(offset + 16)])

	recipientOffset := offset + 12
	transaction.RecipientId = base58.Encode(bytes[recipientOffset:(recipientOffset + 21)])

	return transaction.ParseSignatures(assetOffset + (21+12)*2)
}

func deserializeSecondSignatureRegistration(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	transaction.Asset = &TransactionAsset{}
	transaction.Asset.Signature = &SecondSignatureRegistrationAsset{}
	transaction.Asset.Signature.PublicKey = transaction.Serialized[assetOffset:(assetOffset + 66)]

	return transaction.ParseSignatures(assetOffset + 66)
}

func deserializeDelegateRegistration(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	usernameLength := bytes[offset:(offset + 1)][0]

	transaction.Asset = &TransactionAsset{}
	transaction.Asset.Delegate = &DelegateAsset{}
	transaction.Asset.Delegate.Username = string(bytes[(offset + 1):((offset + 1) + int(usernameLength))])

	return transaction.ParseSignatures(assetOffset + (int(usernameLength)+1)*2)
}

func deserializeVote(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	voteLength := bytes[offset:(offset + 1)][0]

	transaction.Asset = &TransactionAsset{}

	for i := 0; i < int(voteLength); i++ {
		offsetStart := assetOffset + 2 + i*2*34
		offsetEnd := assetOffset + 2 + (i+1)*2*34

		vote := transaction.Serialized[offsetStart:offsetEnd]
		voteType, _ := strconv.Atoi(vote[:2])

		if voteType == 1 {
			transaction.Asset.Votes = append(transaction.Asset.Votes, fmt.Sprintf("%s%s", "+", vote[2:]))
		} else {
			transaction.Asset.Votes = append(transaction.Asset.Votes, fmt.Sprintf("%s%s", "-", vote[2:]))
		}
	}

	return transaction.ParseSignatures(assetOffset + 2 + (int(voteLength)*34)*2)
}

func deserializeMultiSignatureRegistration(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	transaction.Asset = &TransactionAsset{}
	transaction.Asset.MultiSignature = &MultiSignatureRegistrationAsset{}

	transaction.Asset.MultiSignature.Min = bytes[offset]
	transaction.Asset.MultiSignature.Lifetime = bytes[(offset + 2)]

	count := int(bytes[offset+1])
	for i := 0; i < count; i++ {
		offsetStart := assetOffset + 6 + i*66
		offsetEnd := assetOffset + 6 + (i+1)*66

		key := transaction.Serialized[offsetStart:offsetEnd]

		transaction.Asset.MultiSignature.Keysgroup = append(transaction.Asset.MultiSignature.Keysgroup, key)
	}

	return transaction.ParseSignatures(assetOffset + 6 + count*66)
}

func deserializeIpfs(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	dagLength := int(bytes[offset:(offset + 1)][0])

	offsetStart := assetOffset + 2
	offsetEnd := assetOffset + 2 + dagLength*2

	transaction.Asset = &TransactionAsset{
		Dag: transaction.Serialized[offsetStart:offsetEnd],
	}

	return transaction.ParseSignatures(assetOffset + 2*dagLength*2)
}

func deserializeTimelockTransfer(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	transaction.Amount = FlexToshi(binary.LittleEndian.Uint64(bytes[offset:(offset + 8)]))
	transaction.Expiration = binary.LittleEndian.Uint32(bytes[(offset + 8):(offset + 16)])

	recipientOffset := offset + 13
	transaction.RecipientId = base58.Encode(bytes[recipientOffset:(recipientOffset + 21)])

	return transaction.ParseSignatures(assetOffset + (21+13)*2)
}

func deserializeMultiPayment(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	offset := assetOffset / 2

	total := int(binary.LittleEndian.Uint16(bytes[offset:(offset + 4)]))
	offset = assetOffset/2 + 1

	transaction.Asset = &TransactionAsset{}

	for i := 0; i < total; i++ {
		payment := &MultiPaymentAsset{}
		payment.Amount = FlexToshi(binary.LittleEndian.Uint64(bytes[offset:(offset + 8)]))
		recipientOffset := offset + 1
		payment.RecipientId = base58.Encode(bytes[recipientOffset:(recipientOffset + 21)])

		transaction.Asset.Payments = append(transaction.Asset.Payments, payment)

		offset += 22
	}

	for i := 0; i < len(transaction.Asset.Payments); i++ {
		transaction.Amount += transaction.Asset.Payments[i].Amount
	}

	return transaction.ParseSignatures(offset * 2)
}

func deserializeDelegateResignation(assetOffset int, bytes []byte, transaction *Transaction) *Transaction {
	return transaction
}
