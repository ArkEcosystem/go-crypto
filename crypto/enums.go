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
		ValidatorRegistration: 2,
		Vote: 3,
		MultiSignatureRegistration: 4,
		MultiPayment: 6,
		ValidatorResignation: 7,
		UsernameRegistration: 8,
		UsernameResignation: 9,
	}
	TRANSACTION_TYPE_GROUPS = &TransactionTypeGroups{
		Test: 0,
		Core: 1,
	}
	TRANSACTION_FEES = &TransactionFees{
		Transfer: 10000000,
		ValidatorRegistration: 2500000000,
		Vote: 100000000,
		MultiSignatureRegistration: 500000000,
		MultiPayment: 10000000,
		ValidatorResignation: 2500000000,
		UsernameRegistration: 2500000000,
		UsernameResignation: 2500000000,
	}
)

const (
	SIGNATURE_TYPE_ECDSA = 0
	SIGNATURE_TYPE_SCHNORR = 1
)
