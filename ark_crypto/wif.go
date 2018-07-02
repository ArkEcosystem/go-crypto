// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
    "./base58"
)

/*
 Usage
 ===============================================================================
 privateKey, _ := crypto.PrivateKeyFromSecret("passphrase", crypto.NETWORKS_DEVNET)
 privateKey.WIF()
 */
func (privateKey *PrivateKey) WIF() string {
    p := privateKey.Serialize()

    if privateKey.PublicKey.isCompressed {
        p = append(p, 0x1)
    }

    p = append(p, 0x0)
    copy(p[1:], p[:len(p)-1])
    p[0] = privateKey.PublicKey.network.Wif

    return base58.Encode(p)
}
