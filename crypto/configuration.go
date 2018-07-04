// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package arkecosystem_crypto

var (
	CONFIG_NETWORK = &Network{}
)

func GetNetwork() *Network {
	if CONFIG_NETWORK.Nethash == "" {
		return NETWORKS_DEVNET
	}

	return CONFIG_NETWORK
}

func SetNetwork(network *Network) {
	CONFIG_NETWORK = network
}

// func GetFee() {

// }

// func SetFee() {

// }
