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
	expected := map[string]interface{}{"Message": "Hello World", "PublicKey": "034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192", "Signature": "304402200fb4adddd1f1d652b544ea6ab62828a0a65b712ed447e2538db0caebfa68929e02205ecb2e1c63b29879c2ecf1255db506d671c8b3fa6017f67cfd1bf07e6edd1cc8"}

	assert := assert.New(t)
	assert.EqualValues(expected, actual)
}

func TestMessageToJson(t *testing.T) {
	fixture := GetMessageFixture()

	message, _ := SignMessage(fixture.Data.Message, fixture.Passphrase)

	actual, _ := message.ToJson()
	expected := "{\"message\":\"Hello World\",\"publickey\":\"034151a3ec46b5670a682b0a63394f863587d1bc97483b1b6c70eb58e7f0aed192\",\"signature\":\"304402200fb4adddd1f1d652b544ea6ab62828a0a65b712ed447e2538db0caebfa68929e02205ecb2e1c63b29879c2ecf1255db506d671c8b3fa6017f67cfd1bf07e6edd1cc8\"}"

	assert := assert.New(t)
	assert.Equal(expected, actual)
}
