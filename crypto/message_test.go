package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignMessageMatchesPhpTsFixture cross-checks against php-crypto's/
// typescript-crypto's own message-sign fixture (same message and passphrase),
// proving the personal_sign hash construction is byte-identical across SDKs.
func TestSignMessageMatchesPhpTsFixture(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	fixture := GetMessageFixture()

	signed, err := SignMessage(fixture.Data.Message, fixture.Passphrase)
	require.NoError(err)

	assert.Equal(fixture.Data.PublicKey, signed.PublicKey)
	assert.Equal(fixture.Data.Signature, signed.Signature)
}

func TestMessageVerify(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	fixture := GetMessageFixture()

	message := &Message{
		PublicKey: fixture.Data.PublicKey,
		Signature: fixture.Data.Signature,
		Message:   fixture.Data.Message,
	}

	verified, err := message.Verify()
	require.NoError(err)
	assert.True(verified)
}

func TestMessageVerifyRejectsTamperedMessage(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	signed, err := SignMessage("original message", testPassphrase)
	require.NoError(err)

	signed.Message = "tampered message"

	verified, err := signed.Verify()
	require.NoError(err)
	assert.False(verified)
}
