package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicKeyFromPassphrase(t *testing.T) {
	fixture := GetIdentityFixture()

	publicKey, _ := PublicKeyFromPassphrase(fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.PublicKey, publicKey.ToHex())
}

func TestPublicKeyFromHex(t *testing.T) {
	fixture := GetIdentityFixture()

	publicKey, _ := PublicKeyFromHex(fixture.Data.PublicKey)

	assert := assert.New(t)
	assert.Equal(fixture.Data.PublicKey, publicKey.ToHex())
}
