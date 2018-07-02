// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	// "github.com/davecgh/go-spew/spew"
	"strconv"
)

// func GetId() {}
// func GetTransactionBytes() {}
// func VerifyTransaction() {}
// func SecondVerifyTransaction() {}
// func SignTransaction() {}
// func SecondSignTransaction() {}

func ParseSignatures(transaction *Transaction, startOffset int) *Transaction {
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
			// if ('ff' === substr($transaction->secondSignature, 0, 2)) { // start of multi-signature
			//     unset($transaction->secondSignature);
			// } else {
			//     $length2                      = intval(substr($transaction->secondSignature, 2, 2), 16) + 2;
			//     $transaction->secondSignature = substr($transaction->secondSignature, 0, $length2 * 2);
			//     $multiSignatureOffset += $length2 * 2;
			// }
		}

		signatures := transaction.Serialized[:(startOffset + multiSignatureOffset)]

		if len(signatures) == 0 {
			return transaction
		}

		// if 'ff' != signatures[:2] {
		//     return transaction
		// }

		// $signatures              = substr($signatures, 2);
		// $transaction->signatures = [];

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
