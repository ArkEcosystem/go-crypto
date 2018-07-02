// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

type Network struct {
    Epoch   string
    Version byte
    Nethash string
    Wif     byte
}

var MAINNET = &Network{"2017-03-21T13:00:00.000Z", 23, "6e84d08bd299ed97c212c886c98a57e36545c8f5d645ca7eeae63a8bd62d8988", 170}
var DEVNET = &Network{"2017-03-21T13:00:00.000Z", 30, "578e820911f24e039733b45e4882b73e301f813a0d2c31330dafda84534ffa23", 170}
var TESTNET = &Network{"2017-03-21T13:00:00.000Z", 23, "d9acd04bde4234a81addb8482333b4ac906bed7be5a9970ce8ada428bd083192", 186}
