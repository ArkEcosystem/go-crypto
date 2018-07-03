// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	// "github.com/davecgh/go-spew/spew"
	"strings"
)

func SerialiseTransaction(transaction *Transaction) string {
	buffer := new(bytes.Buffer)

	buffer = serialiseHeader(buffer, transaction)
	buffer = serialiseVendorField(buffer, transaction)
	buffer = serialiseTypeSpecific(buffer, transaction)
	buffer = serialiseSignatures(buffer, transaction)

	return HexEncode(buffer.Bytes())
}

////////////////////////////////////////////////////////////////////////////////
// GENERIC SERIALISING /////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func serialiseHeader(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	binary.Write(buffer, binary.LittleEndian, HexDecode("ff")[0])

	if transaction.Version == 0 {
		binary.Write(buffer, binary.LittleEndian, GetNetwork().Version)
	} else {
		binary.Write(buffer, binary.LittleEndian, transaction.Version)
	}

	if transaction.Network == 0 {
		binary.Write(buffer, binary.LittleEndian, HexDecode("01")[0])
	} else {
		binary.Write(buffer, binary.LittleEndian, transaction.Network)
	}

	binary.Write(buffer, binary.LittleEndian, transaction.Type)
	binary.Write(buffer, binary.LittleEndian, transaction.Timestamp)
	binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.SenderPublicKey))
	binary.Write(buffer, binary.LittleEndian, transaction.Fee)

	return buffer
}

func serialiseVendorField(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	if transaction.VendorField != "" {
		vendorFieldLength := len(transaction.VendorField)

		binary.Write(buffer, binary.LittleEndian, uint8(vendorFieldLength))
		binary.Write(buffer, binary.LittleEndian, []byte(transaction.VendorField))
	} else if len(transaction.VendorFieldHex) > 0 {
		vendorFieldHexLength := len(transaction.VendorFieldHex)

		binary.Write(buffer, binary.LittleEndian, uint8(vendorFieldHexLength/2))
		binary.Write(buffer, binary.LittleEndian, []byte(transaction.VendorFieldHex))
	} else {
		binary.Write(buffer, binary.LittleEndian, HexDecode("00")[0])
	}

	return buffer
}

func serialiseTypeSpecific(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	transactionType := uint32(transaction.Type)

	switch {
	case transactionType == TRANSACTION_TYPES.Transfer:
		buffer = serialiseTransfer(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.SecondSignatureRegistration:
		buffer = serialiseSecondSignatureRegistration(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.DelegateRegistration:
		buffer = serialiseDelegateRegistration(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.Vote:
		buffer = serialiseVote(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.MultiSignatureRegistration:
		buffer = serialiseMultiSignatureRegistration(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.Ipfs:
		buffer = serialiseIpfs(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.TimelockTransfer:
		buffer = serialiseTimelockTransfer(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.MultiPayment:
		buffer = serialiseMultiPayment(buffer, transaction)
	case transactionType == TRANSACTION_TYPES.DelegateResignation:
		buffer = serialiseDelegateResignation(buffer, transaction)
	}

	return buffer
}

func serialiseSignatures(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	if transaction.Signature != "" {
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.Signature))
	}

	if transaction.SecondSignature != "" {
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.SecondSignature))
	} else if transaction.SignSignature != "" {
		binary.Write(buffer, binary.LittleEndian, HexDecode(transaction.SignSignature))
	}

	if len(transaction.Signatures) > 0 {
		binary.Write(buffer, binary.LittleEndian, HexDecode("ff")[0])
		binary.Write(buffer, binary.LittleEndian, HexDecode(strings.Join(transaction.Signatures, "")))
	}

	return buffer
}

////////////////////////////////////////////////////////////////////////////////
// TYPE SPECIFIC SERIALISING ///////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func serialiseTransfer(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	binary.Write(buffer, binary.LittleEndian, uint64(transaction.Amount))

	if transaction.Expiration == 0 {
		binary.Write(buffer, binary.LittleEndian, uint32(0))
	} else {
		binary.Write(buffer, binary.LittleEndian, transaction.Expiration)
	}

	binary.Write(buffer, binary.LittleEndian, Base58Decode(transaction.RecipientId))

	return buffer
}

func serialiseSecondSignatureRegistration(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	signatureBytes := HexDecode(transaction.Asset.Signature.PublicKey)

	binary.Write(buffer, binary.LittleEndian, signatureBytes)

	return buffer
}

func serialiseDelegateRegistration(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	delegateBytes := []byte(transaction.Asset.Delegate.Username)

	binary.Write(buffer, binary.LittleEndian, uint8(len(delegateBytes)))
	binary.Write(buffer, binary.LittleEndian, delegateBytes)

	return buffer
}

func serialiseVote(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	voteBytes := make([]string, len(transaction.Asset.Votes))

	for _, element := range transaction.Asset.Votes {
		if element[:1] == "+" {
			voteBytes = append(voteBytes, fmt.Sprintf("%s%s", "01", element[1:]))
		} else {
			voteBytes = append(voteBytes, fmt.Sprintf("%s%s", "00", element[1:]))
		}
	}

	binary.Write(buffer, binary.LittleEndian, uint8(len(transaction.Asset.Votes)))
	binary.Write(buffer, binary.LittleEndian, HexDecode(strings.Join(voteBytes, "")))

	return buffer
}

func serialiseMultiSignatureRegistration(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	keysgroup := make([]string, len(transaction.Asset.MultiSignature.Keysgroup))

	if transaction.Version == 1 {
		for _, element := range transaction.Asset.MultiSignature.Keysgroup {
			if element[:1] == "+" {
				keysgroup = append(keysgroup, element[1:])
			} else {
				keysgroup = append(keysgroup, element)
			}
		}
	} else {
		keysgroup = transaction.Asset.MultiSignature.Keysgroup
	}

	binary.Write(buffer, binary.LittleEndian, uint8(transaction.Asset.MultiSignature.Min))
	binary.Write(buffer, binary.LittleEndian, uint8(len(transaction.Asset.MultiSignature.Keysgroup)))
	binary.Write(buffer, binary.LittleEndian, uint8(transaction.Asset.MultiSignature.Lifetime))
	binary.Write(buffer, binary.LittleEndian, HexDecode(strings.Join(keysgroup, "")))

	return buffer
}

func serialiseIpfs(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	return buffer
}

func serialiseTimelockTransfer(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	return buffer
}

func serialiseMultiPayment(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	return buffer
}

func serialiseDelegateResignation(buffer *bytes.Buffer, transaction *Transaction) *bytes.Buffer {
	return buffer
}
