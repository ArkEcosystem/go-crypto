// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPublicKeyFromSecret(t *testing.T) {
	publicKey, _ := PublicKeyFromSecret("this is a top secret passphrase")

	assert := assert.New(t)
	assert.Equal("034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192", publicKey.toHex())
}

func TestPublicKeyFromHex(t *testing.T) {
	publicKey, _ := PublicKeyFromHex("034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192")

	assert := assert.New(t)
	assert.Equal("034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192", publicKey.toHex())
}
