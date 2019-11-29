// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

var (
	TRANSACTION_TYPES = &TransactionTypes{
		Transfer: 0,
		SecondSignatureRegistration: 1,
		DelegateRegistration: 2,
		Vote: 3,
		MultiSignatureRegistration: 4,
		Ipfs: 5,
		MultiPayment: 6,
		DelegateResignation: 7,
		HtlcLock: 8,
		HtlcClaim: 9,
		HtlcRefund: 10,
	}
	TRANSACTION_TYPE_GROUPS = &TransactionTypeGroups{
		Test: 0,
		Core: 1,
	}
	TRANSACTION_FEES = &TransactionFees{
		Transfer: 10000000,
		SecondSignatureRegistration: 500000000,
		DelegateRegistration: 2500000000,
		Vote: 100000000,
		MultiSignatureRegistration: 500000000,
		Ipfs: 500000000,
		MultiPayment: 10000000,
		DelegateResignation: 2500000000,
		HtlcLock: 10000000,
		HtlcClaim: 0,
		HtlcRefund: 0,
	}
)

const (
	SIGNATURE_TYPE_ECDSA = 0
	SIGNATURE_TYPE_SCHNORR = 1
)
