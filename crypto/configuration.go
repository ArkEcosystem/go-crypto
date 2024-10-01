// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

var (
	CONFIG_NETWORK = &Network{}
	CONFIG_FEES = map[uint16]FlexToshi{
		TRANSACTION_TYPES.Transfer:                 TRANSACTION_FEES.Transfer,
		TRANSACTION_TYPES.ValidatorRegistration:    TRANSACTION_FEES.ValidatorRegistration,
		TRANSACTION_TYPES.Vote:                     TRANSACTION_FEES.Vote,
		TRANSACTION_TYPES.MultiSignatureRegistration: TRANSACTION_FEES.MultiSignatureRegistration,
		TRANSACTION_TYPES.MultiPayment:             TRANSACTION_FEES.MultiPayment,
		TRANSACTION_TYPES.ValidatorResignation:     TRANSACTION_FEES.ValidatorResignation,
		TRANSACTION_TYPES.UsernameRegistration:     TRANSACTION_FEES.UsernameRegistration,
		TRANSACTION_TYPES.UsernameResignation:      TRANSACTION_FEES.UsernameResignation,
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
