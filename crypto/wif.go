// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
)

/*
 Usage
 ===============================================================================
 privateKey, _ := crypto.PrivateKeyFromSecret("passphrase")
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
