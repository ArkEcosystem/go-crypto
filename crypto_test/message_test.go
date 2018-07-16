// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto_test

import (
	"testing"

	"github.com/ArkEcosystem/go-crypto/crypto"
	"github.com/stretchr/testify/assert"
)

func TestSignMessage(t *testing.T) {
	fixture := GetMessageFixture()

	message, _ := crypto.SignMessage(fixture.Data.Message, fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.PublicKey, message.PublicKey)
	assert.Equal(fixture.Data.Signature, message.Signature)
	assert.Equal(fixture.Data.Message, message.Message)
}

func TestVerifyMessage(t *testing.T) {
	fixture := GetMessageFixture()

	message, _ := crypto.SignMessage(fixture.Data.Message, fixture.Passphrase)

	assert := assert.New(t)
	assert.True(message.Verify())
}
