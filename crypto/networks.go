// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package arkecosystem_crypto

import "time"

var (
	NETWORKS_MAINNET = &Network{
		Epoch:   time.Date(2017, 3, 21, 13, 00, 0, 0, time.UTC),
		Version: 23,
		Nethash: "6e84d08bd299ed97c212c886c98a57e36545c8f5d645ca7eeae63a8bd62d8988",
		Wif:     170,
	}
	NETWORKS_DEVNET = &Network{
		Epoch:   time.Date(2017, 3, 21, 13, 00, 0, 0, time.UTC),
		Version: 30,
		Nethash: "578e820911f24e039733b45e4882b73e301f813a0d2c31330dafda84534ffa23",
		Wif:     170,
	}
	NETWORKS_TESTNET = &Network{
		Epoch:   time.Date(2017, 3, 21, 13, 00, 0, 0, time.UTC),
		Version: 23,
		Nethash: "d9acd04bde4234a81addb8482333b4ac906bed7be5a9970ce8ada428bd083192",
		Wif:     186,
	}
)
