// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

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
