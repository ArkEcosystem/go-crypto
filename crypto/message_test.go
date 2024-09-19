// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignMessage(t *testing.T) {
	CONFIG_SIGNATURE_TYPE = SIGNATURE_TYPE_ECDSA

	fixture := GetMessageFixture()

	message, _ := SignMessage(fixture.Data.Message, fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.PublicKey, message.PublicKey)
	assert.Equal(fixture.Data.Signature, message.Signature)
	assert.Equal(fixture.Data.Message, message.Message)
}

func TestVerifyMessage(t *testing.T) {
	fixture := GetMessageFixture()

	message, _ := SignMessage(fixture.Data.Message, fixture.Passphrase)

	assert := assert.New(t)
	assert.True(message.Verify())
}

func TestMessageToMap(t *testing.T) {
	fixture := GetMessageFixture()

	message, _ := SignMessage(fixture.Data.Message, fixture.Passphrase)

	actual := message.ToMap()
	expected := map[string]interface{}{"Message": "Hello World", "PublicKey": "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192", "Signature": "cdc26c4d137dbbad22ec94fee0bb7d7c1864291aec69c5d30a2d585efb2aa5e349e5497bb94221d8394e56a04e9b39cf9960c73b8212f46d2f03597cd73ebd33"}

	assert := assert.New(t)
	assert.EqualValues(expected, actual)
}

func TestMessageToJson(t *testing.T) {
	fixture := GetMessageFixture()

	message, _ := SignMessage(fixture.Data.Message, fixture.Passphrase)

	actual, _ := message.ToJson()
	expected := "{\"message\":\"Hello World\",\"publickey\":\"034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192\",\"signature\":\"cdc26c4d137dbbad22ec94fee0bb7d7c1864291aec69c5d30a2d585efb2aa5e349e5497bb94221d8394e56a04e9b39cf9960c73b8212f46d2f03597cd73ebd33\"}"

	assert := assert.New(t)
	assert.Equal(expected, actual)
}
