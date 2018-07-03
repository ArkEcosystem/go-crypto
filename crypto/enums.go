// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

var (
	TRANSACTION_TYPES = &TransactionTypes{
		Transfer:                    0,
		SecondSignatureRegistration: 1,
		DelegateRegistration:        2,
		Vote:                        3,
		MultiSignatureRegistration: 4,
		Ipfs:                5,
		TimelockTransfer:    6,
		MultiPayment:        7,
		DelegateResignation: 8,
	}
	TRANSACTION_FEES = &TransactionFees{
		Transfer:                    10000000,
		SecondSignatureRegistration: 500000000,
		DelegateRegistration:        2500000000,
		Vote:                        100000000,
		MultiSignatureRegistration: 500000000,
		Ipfs:                0,
		TimelockTransfer:    0,
		MultiPayment:        0,
		DelegateResignation: 0,
	}
)
