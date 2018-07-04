// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package arkecosystem_crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
	"log"
	"strconv"
	"strings"
)

func (transaction *Transaction) GetId() string {
	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(false, false))

	return HexEncode(bytes.Sum(nil))
}

func (transaction *Transaction) Sign(secret string) {
	privateKey, _ := PrivateKeyFromSecret(secret)

	transaction.SenderPublicKey = HexEncode(privateKey.PublicKey.Serialize())
	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(true, true))

	signature, err := privateKey.Sign(bytes.Sum(nil))
	if err == nil {
		transaction.Signature = HexEncode(signature)
	}
}

func (transaction *Transaction) SecondSign(secret string) {
	privateKey, _ := PrivateKeyFromSecret(secret)

	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(false, true))

	signature, err := privateKey.Sign(bytes.Sum(nil))
	if err == nil {
		transaction.SignSignature = HexEncode(signature)
	}
}

func (transaction *Transaction) Verify() (bool, error) {
	publicKey, err := PublicKeyFromBytes(HexDecode(transaction.SenderPublicKey))

	if err != nil {
		return false, err
	}

	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(true, true))

	return publicKey.Verify(HexDecode(transaction.Signature), bytes.Sum(nil))

}

func (transaction *Transaction) SecondVerify(secondPublicKey *PublicKey) (bool, error) {
	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(false, true))

	return secondPublicKey.Verify(HexDecode(transaction.SignSignature), bytes.Sum(nil))
}

func (transaction *Transaction) ToBytes(skipSignature, skipSecondSignature bool) []byte {
	buffer := new(bytes.Buffer)
	binary.Write(buffer, binary.LittleEndian, transaction.Type)
	binary.Write(buffer, binary.LittleEndian, uint32(transaction.Timestamp))
	binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.SenderPublicKey))

	if transaction.RecipientId != "" {
		res, err := base58.Decode(transaction.RecipientId)

		if err != nil {
			log.Fatal("Error converting Decoding b58 ", err.Error())
		}

		binary.Write(buffer, binary.LittleEndian, res)
	} else {
		binary.Write(buffer, binary.LittleEndian, make([]byte, 21))
	}

	if transaction.VendorField != "" {
		vendorBytes := []byte(transaction.VendorField)
		if len(vendorBytes) < 65 {
			binary.Write(buffer, binary.LittleEndian, vendorBytes)

			bs := make([]byte, 64-len(vendorBytes))
			binary.Write(buffer, binary.LittleEndian, bs)
		}
	} else {
		binary.Write(buffer, binary.LittleEndian, make([]byte, 64))
	}

	binary.Write(buffer, binary.LittleEndian, uint64(transaction.Amount))
	binary.Write(buffer, binary.LittleEndian, uint64(transaction.Fee))

	switch transaction.Type {
	case TRANSACTION_TYPES.SecondSignatureRegistration:
		// FIX: no longer works, results in a wrong ID later on
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.Asset.Signature.PublicKey))
	case TRANSACTION_TYPES.DelegateRegistration:
		usernameBytes := []byte(transaction.Asset.Delegate.Username)
		binary.Write(buffer, binary.LittleEndian, usernameBytes)
	case TRANSACTION_TYPES.Vote:
		// FIX: no longer works, results in a wrong ID later on
		voteBytes := []byte(strings.Join(transaction.Asset.Votes, ""))
		binary.Write(buffer, binary.LittleEndian, voteBytes)
	case TRANSACTION_TYPES.MultiSignatureRegistration:
		keysgroup := []byte(strings.Join(transaction.Asset.MultiSignature.Keysgroup, ""))
		binary.Write(buffer, binary.LittleEndian, uint8(transaction.Asset.MultiSignature.Min))
		binary.Write(buffer, binary.LittleEndian, uint8(transaction.Asset.MultiSignature.Lifetime))
		binary.Write(buffer, binary.LittleEndian, keysgroup)
	}

	if !skipSignature && len(transaction.Signature) > 0 {
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.Signature))
	}

	if !skipSecondSignature && len(transaction.SignSignature) > 0 {
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.SignSignature))
	}

	return buffer.Bytes()
}

func (transaction *Transaction) ParseSignatures(startOffset int) *Transaction {
	transaction.Signature = transaction.Serialized[startOffset:]

	multiSignatureOffset := 0

	if len(transaction.Signature) == 0 {
		transaction.Signature = ""
	} else {
		length1, _ := strconv.ParseInt(transaction.Signature[2:4], 16, 64)
		length1 += 2

		signatureOffset := startOffset + int(length1)*2
		transaction.Signature = transaction.Serialized[startOffset:signatureOffset]

		multiSignatureOffset += int(length1) * 2
		transaction.SecondSignature = string(transaction.Serialized[signatureOffset:])

		if len(transaction.SecondSignature) == 0 {
			transaction.SecondSignature = ""
		} else {
			if "ff" == transaction.SecondSignature[:2] { // start of multi-signature
				transaction.SecondSignature = ""
			} else {
				length2, _ := strconv.ParseInt(transaction.SecondSignature[2:4], 16, 64)
				length2 += 2

				transaction.SecondSignature = transaction.SecondSignature[:(length2 * 2)]
				multiSignatureOffset += int(length2) * 2
			}
		}

		signatures := transaction.Serialized[(startOffset + multiSignatureOffset):]

		if len(signatures) == 0 {
			return transaction
		}

		if "ff" != signatures[:2] {
			return transaction
		}

		signatures = signatures[2:]
		moreSignatures := true
		for moreSignatures {
			if signatures == "" {
				return transaction
			}

			multiSignatureLength, _ := strconv.ParseInt(signatures[2:4], 16, 64)
			multiSignatureLength += 2

			if multiSignatureLength > 0 {
				transaction.Signatures = append(transaction.Signatures, signatures[:(multiSignatureLength*2)])
			} else {
				moreSignatures = false
			}

			signatures = signatures[(multiSignatureLength * 2):]
		}
	}

	return transaction
}
