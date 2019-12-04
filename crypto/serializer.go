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
	"fmt"
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

func (transaction *Transaction) serialize(includeSignature bool, includeSecondSignature bool) []byte {
	ser := new(bytes.Buffer)

    transaction.serializeHeader(ser)
    transaction.serializeVendorField(ser)
    transaction.serializeTypeSpecific(ser)
    transaction.serializeSignatures(ser, includeSignature, includeSecondSignature)

    return ser.Bytes()
}

func (transaction *Transaction) serializeHeader(ser *bytes.Buffer) {
	ser.WriteByte(uint8(0xFF))

	if transaction.Version == 2 {
		ser.WriteByte(transaction.Version)
	} else {
		log.Fatal("Serialization is only implemented for version 2 transactions")
	}

	if transaction.Network == 0 {
		ser.WriteByte(GetNetwork().Version)
	} else {
		ser.WriteByte(transaction.Network)
	}

	binary.Write(ser, binary.LittleEndian, transaction.TypeGroup)
	binary.Write(ser, binary.LittleEndian, transaction.Type)
	binary.Write(ser, binary.LittleEndian, transaction.Nonce)
	ser.Write(HexDecode(transaction.SenderPublicKey))
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
	case TRANSACTION_TYPES.SecondSignatureRegistration:
		transaction.serializeSecondSignatureRegistration(ser)
	case TRANSACTION_TYPES.DelegateRegistration:
		transaction.serializeDelegateRegistration(ser)
	case TRANSACTION_TYPES.Vote:
		transaction.serializeVote(ser)
	case TRANSACTION_TYPES.MultiSignatureRegistration:
		transaction.serializeMultiSignatureRegistration(ser)
	case TRANSACTION_TYPES.Ipfs:
		transaction.serializeIpfs(ser)
	case TRANSACTION_TYPES.MultiPayment:
		transaction.serializeMultiPayment(ser)
	case TRANSACTION_TYPES.DelegateResignation:
		transaction.serializeDelegateResignation(ser)
	case TRANSACTION_TYPES.HtlcLock:
		transaction.serializeHtlcLock(ser)
	case TRANSACTION_TYPES.HtlcClaim:
		transaction.serializeHtlcClaim(ser)
	case TRANSACTION_TYPES.HtlcRefund:
		transaction.serializeHtlcRefund(ser)
	}
}

func (transaction *Transaction) serializeSignatures(ser *bytes.Buffer, includeSignature bool, includeSecondSignature bool) {
	if includeSignature && transaction.Signature != "" {
		ser.Write(HexDecode(transaction.Signature))
	}

	if includeSecondSignature && transaction.SecondSignature != "" {
		ser.Write(HexDecode(transaction.SecondSignature))
	}

	if len(transaction.Signatures) > 0 {
		ser.WriteByte(uint8(0xFF))
		ser.Write(HexDecode(strings.Join(transaction.Signatures, "")))
	}
}

func (transaction *Transaction) serializeTransfer(ser *bytes.Buffer) {
	binary.Write(ser, binary.LittleEndian, uint64(transaction.Amount))
	binary.Write(ser, binary.LittleEndian, transaction.Expiration)
	ser.Write(Base58CheckDecodeFatal(transaction.RecipientId))
}

func (transaction *Transaction) serializeSecondSignatureRegistration(ser *bytes.Buffer) {
	ser.Write(HexDecode(transaction.Asset.Signature.PublicKey))
}

func (transaction *Transaction) serializeDelegateRegistration(ser *bytes.Buffer) {
	delegateBytes := []byte(transaction.Asset.Delegate.Username)

	writeNumberAsByte(ser, len(delegateBytes), "delegate username")
	ser.Write(delegateBytes)
}

func (transaction *Transaction) serializeVote(ser *bytes.Buffer) {
	voteStrings := make([]string, 0)

	for _, element := range transaction.Asset.Votes {
		pfx := "00"
		if element[:1] == "+" {
			pfx = "01"
		}
		voteStrings = append(voteStrings, fmt.Sprintf("%s%s", pfx, element[1:]))
	}

	writeNumberAsByte(ser, len(transaction.Asset.Votes), "number of votes")
	ser.Write(HexDecode(strings.Join(voteStrings, "")))
}

func (transaction *Transaction) serializeMultiSignatureRegistration(ser *bytes.Buffer) {
	publicKeys := transaction.Asset.MultiSignature.PublicKeys

	ser.WriteByte(transaction.Asset.MultiSignature.Min)
	writeNumberAsByte(ser, len(publicKeys), "number of public keys in multisig")
	ser.Write(HexDecode(strings.Join(publicKeys, "")))
}

func (transaction *Transaction) serializeIpfs(ser *bytes.Buffer) {
	ser.Write(b58.Decode(transaction.Asset.Ipfs))
}

func (transaction *Transaction) serializeMultiPayment(ser *bytes.Buffer) {
	binary.Write(ser, binary.LittleEndian, uint16(len(transaction.Asset.Payments)))

	for _, element := range transaction.Asset.Payments {
		binary.Write(ser, binary.LittleEndian, uint64(element.Amount))
		ser.Write(Base58CheckDecodeFatal(element.RecipientId))
	}
}

func (transaction *Transaction) serializeDelegateResignation(buffer *bytes.Buffer) {
	// noop
}

func (transaction *Transaction) serializeHtlcLock(ser *bytes.Buffer) {
	binary.Write(ser, binary.LittleEndian, uint64(transaction.Amount))
	ser.Write(HexDecode(transaction.Asset.Lock.SecretHash))
	ser.WriteByte(transaction.Asset.Lock.Expiration.Type)
	binary.Write(ser, binary.LittleEndian, transaction.Asset.Lock.Expiration.Value)
	ser.Write(Base58CheckDecodeFatal(transaction.RecipientId))
}

func (transaction *Transaction) serializeHtlcClaim(ser *bytes.Buffer) {
	ser.Write(HexDecode(transaction.Asset.Claim.LockTransactionId))
	ser.Write([]byte(transaction.Asset.Claim.UnlockSecret))
}

func (transaction *Transaction) serializeHtlcRefund(ser *bytes.Buffer) {
	ser.Write(HexDecode(transaction.Asset.Refund.LockTransactionId))
}
