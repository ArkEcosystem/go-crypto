// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/json"
	"log"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func compareTransactions(t *testing.T, expected, actual Transaction) {
	assert := assert.New(t)
	assert.Equal(expected.Amount, actual.Amount, "Amount does not match")
	assert.Equal(expected.Fee, actual.Fee, "Fee does not match")
	assert.Equal(expected.Expiration, actual.Expiration, "Expiration does not match")
	assert.Equal(expected.Id, actual.Id, "Id does not match")
	assert.Equal(expected.Network, actual.Network, "Network does not match")
	assert.Equal(expected.Nonce, actual.Nonce, "Nonce does not match")
	assert.Equal(expected.RecipientId, actual.RecipientId, "RecipientId does not match")
	assert.Equal(expected.SenderPublicKey, actual.SenderPublicKey, "SenderPublicKey does not match")
	assert.Equal(expected.Signature, actual.Signature, "Signature does not match")
	assert.Equal(expected.Type, actual.Type, "Type does not match")
	assert.Equal(expected.TypeGroup, actual.TypeGroup, "TypeGroup does not match")
	assert.Equal(expected.Version, actual.Version, "Version does not match")
}

func commonSerDeserTest(t *testing.T, fixturePath string) {
	fixtureJson := []byte(GetFile(fixturePath))

	var fixture TestingFixture

	err := json.Unmarshal(fixtureJson, &fixture)
	if err != nil {
		log.Fatalf("Cannot parse fixture JSON %s: %s", fixturePath, err)
	}

	fixture.Transaction.Serialized = HexDecode(fixture.SerializedHex)

	transaction := DeserializeTransaction(fixture.SerializedHex)

	assert := assert.New(t)

	compareTransactions(t, fixture.Transaction, *transaction)

	assert.Equal(fixture.SerializedHex, HexEncode(transaction.serialize(true, true, true)))

	assert.True(transaction.Verify(&fixture.MultiSignatureAsset))
}

func TestSerDeser(t *testing.T) {
	directory := "fixtures/transactions/"
	files, _ := filepath.Glob(directory + "*/*.json")

	for _, file := range files {
		test := func (t *testing.T) {
			commonSerDeserTest(t, file)
		}

		subTestName := file[len(directory):len(file) - len(".json")]

		t.Run(subTestName, test)
	}
}
