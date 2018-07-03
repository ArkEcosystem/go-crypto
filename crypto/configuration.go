// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

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
