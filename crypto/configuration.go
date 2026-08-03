package crypto

var CONFIG_NETWORK = &Network{}

func GetNetwork() *Network {
	if CONFIG_NETWORK.ChainId == 0 {
		return NETWORKS_TESTNET
	}

	return CONFIG_NETWORK
}

func SetNetwork(network *Network) {
	CONFIG_NETWORK = network
}
