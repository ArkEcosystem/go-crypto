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
		TRANSACTION_FEES.TimelockTransfer,
		TRANSACTION_FEES.MultiPayment,
		TRANSACTION_FEES.DelegateResignation,
	}
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

func GetFee(transactionType byte) FlexToshi {
	return CONFIG_FEES[transactionType]
}

func SetFee(transactionType byte, value FlexToshi) {
	CONFIG_FEES[transactionType] = value
}
