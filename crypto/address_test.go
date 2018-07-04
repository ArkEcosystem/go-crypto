// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package arkecosystem_crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAddressFromSecret(t *testing.T) {
	address, _ := AddressFromSecret("this is a top secret passphrase")

	assert := assert.New(t)
	assert.Equal("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib", address)
}

func TestValidateAddress(t *testing.T) {
	assert := assert.New(t)
	assert.True(ValidateAddress("D61mfSggzbvQgTUe6JhYKH2doHaqJ3Dyib"))
}
