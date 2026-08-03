package crypto

import "time"

var (
	NETWORKS_MAINNET = &Network{
		Epoch:   time.Date(2017, 3, 21, 13, 00, 0, 0, time.UTC),
		ChainId: 11811,
		Wif:     186,
	}
	NETWORKS_TESTNET = &Network{
		Epoch:   time.Date(2017, 3, 21, 13, 00, 0, 0, time.UTC),
		ChainId: 11812,
		Wif:     186,
	}
)
