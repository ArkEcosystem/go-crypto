// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto_test

import (
	"testing"

	. "github.com/ArkEcosystem/go-crypto/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSignMessage(t *testing.T) {
	message, _ := crypto.SignMessage("Hello World", "This is a top secret passphrase")

	assert := assert.New(t)
	assert.Equal("0366f4352b1f8456b0b43e8109522333931f51d7c685ea7c7d60a3cff51e7724a0", message.PublicKey)
	assert.Equal("3045022100ef95928c81a034f0a81ff3d458140ef67ddced6632d9d72bca27ae9e0144ec4502206844c354f87757756b7035d30c8804dbafef8ca2760e20d4939269f360caba83", message.Signature)
	assert.Equal("Hello World", message.Message)
}

func TestVerifyMessage(t *testing.T) {
	message, _ := crypto.SignMessage("Hello World", "This is a top secret passphrase")

	assert := assert.New(t)
	assert.True(message.Verify())
}
