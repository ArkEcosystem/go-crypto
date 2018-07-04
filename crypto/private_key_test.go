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

func TestPrivateKeyFromSecret(t *testing.T) {
	privateKey, _ := PrivateKeyFromSecret("this is a top secret passphrase")

	assert := assert.New(t)
	assert.Equal("d8839c2432bfd0a67ef10a804ba991eabba19f154a3d707917681d45822a5712", privateKey.ToHex())
}

func TestPrivateKeyToAddress(t *testing.T) {
	privateKey, _ := PrivateKeyFromSecret("this is a top secret passphrase")

	assert := assert.New(t)
	assert.Equal("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", privateKey.ToAddress())
}

func TestPrivateKeyToWif(t *testing.T) {
	privateKey, _ := PrivateKeyFromSecret("this is a top secret passphrase")

	assert := assert.New(t)
	assert.Equal("SGq4xLgZKCGxs7bjmwnBrWcT4C1ADFEermj846KC97FSv1WFD1dA", privateKey.ToWif())
}
