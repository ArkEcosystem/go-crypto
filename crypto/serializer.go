// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"bytes"
	"encoding/binary"
	"log"
	"strings"

	b58 "github.com/btcsuite/btcutil/base58"
)

func writeNumberAsByte(ser *bytes.Buffer, num interface{}, name string) {
	numInt := num.(int)

	if numInt > 0xFF {
		log.Fatal("Cannot serialize: max supported", name, "is 256. Provided:", num)
	}

	ser.WriteByte(uint8(numInt))
}

func (transaction *Transaction) serialize(includeSignature bool, includeSecondSignature bool, includeMultiSignatures bool) []byte {
	ser := new(bytes.Buffer)

    transaction.serializeHeader(ser)
    transaction.serializeVendorField(ser)
    transaction.serializeTypeSpecific(ser)
    transaction.serializeSignatures(ser, includeSignature, includeSecondSignature, includeMultiSignatures)

    return ser.Bytes()
}

func (transaction *Transaction) serializeHeader(ser *bytes.Buffer) {
	ser.WriteByte(uint8(0xFF))

	ser.WriteByte(transaction.Version)
	
	if transaction.Network == 0 {
		ser.WriteByte(GetNetwork().Version)
	} else {
		ser.WriteByte(transaction.Network)
	}

	binary.Write(ser, binary.LittleEndian, transaction.TypeGroup)
	binary.Write(ser, binary.LittleEndian, transaction.Type)
	binary.Write(ser, binary.LittleEndian, transaction.Nonce)
	if transaction.SenderPublicKey != "" {
		ser.Write(HexDecode(transaction.SenderPublicKey))
	}
	binary.Write(ser, binary.LittleEndian, uint64(transaction.Fee))
}

func (transaction *Transaction) serializeVendorField(ser *bytes.Buffer) {
	if transaction.VendorField != "" {
		writeNumberAsByte(ser, len(transaction.VendorField), "vendorField")
		ser.Write([]byte(transaction.VendorField))
	} else {
		ser.WriteByte(uint8(0x00))
	}
}

func (transaction *Transaction) serializeTypeSpecific(ser *bytes.Buffer) {
	switch transaction.Type {
	case TRANSACTION_TYPES.Transfer:
		transaction.serializeTransfer(ser)
	case TRANSACTION_TYPES.ValidatorRegistration:
		transaction.serializeValidatorRegistration(ser)
	case TRANSACTION_TYPES.Vote:
		transaction.serializeVote(ser)
	case TRANSACTION_TYPES.MultiSignatureRegistration:
		transaction.serializeMultiSignatureRegistration(ser)
	case TRANSACTION_TYPES.MultiPayment:
		transaction.serializeMultiPayment(ser)
	case TRANSACTION_TYPES.ValidatorResignation:
		transaction.serializeValidatorResignation(ser)
	}
}

func (transaction *Transaction) serializeSignatures(ser *bytes.Buffer, includeSignature bool, includeSecondSignature bool, includeMultiSignatures bool) {
	if includeSignature && transaction.Signature != "" {
		ser.Write(HexDecode(transaction.Signature))
	}

	if includeSecondSignature && transaction.SecondSignature != "" {
		ser.Write(HexDecode(transaction.SecondSignature))
	}

	if includeMultiSignatures && len(transaction.Signatures) > 0 {
		ser.Write(HexDecode(strings.Join(transaction.Signatures, "")))
	}
}

func stripAddressPrefix(recipientId string) string {
	address := recipientId[2:]
	if strings.HasPrefix(address, "0x") {
			address = address[2:]
	}
	return address
}


func (transaction *Transaction) serializeTransfer(ser *bytes.Buffer) {
	binary.Write(ser, binary.LittleEndian, uint64(transaction.Amount))
	binary.Write(ser, binary.LittleEndian, transaction.Expiration)
	
	address := stripAddressPrefix(transaction.RecipientId)
	
	recipientBytes := HexDecode(address)

	ser.Write(recipientBytes)
}

func (transaction *Transaction) serializeValidatorRegistration(ser *bytes.Buffer) {
	ser.Write(HexDecode(transaction.Asset.Validator.ValidatorPublicKey))
}

func (transaction *Transaction) serializeVote(ser *bytes.Buffer) {
	// Serialize Votes
	votes := transaction.Asset.Votes
	unvotes := transaction.Asset.Unvotes

	// Write the number of votes
	writeNumberAsByte(ser, len(votes), "number of votes")

	// Write each vote in hexadecimal format
	for _, vote := range votes {
		ser.Write(HexDecode(vote))
	}

	// Write the number of unvotes
	writeNumberAsByte(ser, len(unvotes), "number of unvotes")

	// Write each unvote in hexadecimal format
	for _, unvote := range unvotes {
		ser.Write(HexDecode(unvote))
	}
}

func (transaction *Transaction) serializeMultiSignatureRegistration(ser *bytes.Buffer) {
	publicKeys := transaction.Asset.MultiSignature.PublicKeys

	ser.WriteByte(transaction.Asset.MultiSignature.Min)
	writeNumberAsByte(ser, len(publicKeys), "number of public keys in multisig")
	ser.Write(HexDecode(strings.Join(publicKeys, "")))
}

func (transaction *Transaction) serializeMultiPayment(ser *bytes.Buffer) {
	binary.Write(ser, binary.LittleEndian, uint16(len(transaction.Asset.Payments)))

	for _, element := range transaction.Asset.Payments {
		binary.Write(ser, binary.LittleEndian, uint64(element.Amount))
		ser.Write(HexDecode(stripAddressPrefix(element.RecipientId)))
	}
}

func (transaction *Transaction) serializeValidatorResignation(buffer *bytes.Buffer) {
	// noop
}

