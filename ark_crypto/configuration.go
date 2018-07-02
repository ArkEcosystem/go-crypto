// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

var (
    NetworkConfiguration = &Network{}
)

func GetNetwork() *Network {
    return NetworkConfiguration
}

func SetNetwork(network *Network) {
    NetworkConfiguration = network
}

// func GetFee() {

// }

// func SetFee() {

// }
