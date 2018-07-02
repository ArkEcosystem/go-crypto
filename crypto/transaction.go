// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	// "github.com/davecgh/go-spew/spew"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
	"log"
	"strconv"
)

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

		signatures := transaction.Serialized[:(startOffset + multiSignatureOffset)]

		if len(signatures) == 0 {
			return transaction
		}

		if "ff" != signatures[:2] {
			return transaction
		}

		// signatures = signatures[2:]
		// transaction.Signatures = []

		// spew.Dump(signatures)
		// $moreSignatures = true;
		// while ($moreSignatures) {
		//     $mLength = intval(substr($signatures, 2, 2), 16);

		//     if ($mLength > 0) {
		//         $transaction->signatures[] = substr($signatures, 0, ($mLength + 2) * 2);
		//     } else {
		//         $moreSignatures = false;
		//     }

		//     $signatures = substr($signatures, ($mLength + 2) * 2);
		// }
	}

	return transaction
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

	switch uint32(transaction.Type) {
	case TRANSACTION_TYPES.SecondSignatureRegistration:
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.Asset["signature"]))
	case TRANSACTION_TYPES.DelegateRegistration:
		usernameBytes := []byte(transaction.Asset["username"])
		binary.Write(buffer, binary.LittleEndian, usernameBytes)
	case TRANSACTION_TYPES.Vote:
		voteBytes := []byte(transaction.Asset["votes"])
		binary.Write(buffer, binary.LittleEndian, voteBytes)
	}

	if !skipSignature && len(transaction.Signature) > 0 {
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.Signature))
	}

	if !skipSecondSignature && len(transaction.SignSignature) > 0 {
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.SignSignature))
	}

	return buffer.Bytes()
}

func (transaction *Transaction) Sign(passphrase string) {
	privateKey, _ := PrivateKeyFromSecret(passphrase)

	// transaction.SenderPublicKey = HexEncode(privateKey.PublicKey.Serialise())

	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(true, true))

	sig, err := privateKey.Sign(bytes.Sum(nil))
	if err == nil {
		transaction.Signature = HexEncode(sig)
	}
}

func (transaction *Transaction) SecondSign(passphrase string) {
	privateKey, _ := PrivateKeyFromSecret(passphrase)

	// transaction.SecondSenderPublicKey = HexEncode(privateKey.PublicKey.Serialise())
	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(false, true))

	sig, err := privateKey.Sign(bytes.Sum(nil))
	if err == nil {
		transaction.SignSignature = HexEncode(sig)
	}
}

func (transaction *Transaction) GetId() string {
	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(false, false))

	return HexEncode(bytes.Sum(nil))
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

func (transaction *Transaction) SecondVerify() (bool, error) {
	publicKey, err := PublicKeyFromBytes(HexDecode(transaction.SecondSenderPublicKey))

	if err != nil {
		return false, err
	}

	bytes := sha256.New()
	bytes.Write(transaction.ToBytes(false, true))

	return publicKey.Verify(HexDecode(transaction.SignSignature), bytes.Sum(nil))
}
