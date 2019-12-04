// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

var (
	CONFIG_NETWORK = &Network{}
	CONFIG_FEES    = []FlexToshi{
		TRANSACTION_FEES.Transfer,
		TRANSACTION_FEES.SecondSignatureRegistration,
		TRANSACTION_FEES.DelegateRegistration,
		TRANSACTION_FEES.Vote,
		TRANSACTION_FEES.MultiSignatureRegistration,
		TRANSACTION_FEES.Ipfs,
		TRANSACTION_FEES.MultiPayment,
		TRANSACTION_FEES.DelegateResignation,
		TRANSACTION_FEES.HtlcLock,
		TRANSACTION_FEES.HtlcClaim,
		TRANSACTION_FEES.HtlcRefund,
	}
	CONFIG_SIGNATURE_TYPE = SIGNATURE_TYPE_SCHNORR
)

func GetNetwork() *Network {
	if CONFIG_NETWORK.Version == 0 {
		return NETWORKS_DEVNET
	}

	return CONFIG_NETWORK
}

func SetNetwork(network *Network) {
	CONFIG_NETWORK = network
}

func GetFee(transactionType uint16) FlexToshi {
	return CONFIG_FEES[transactionType]
}

func SetFee(transactionType uint16, value FlexToshi) {
	CONFIG_FEES[transactionType] = value
}
