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

	assert.Equal(fixture.Transaction, *transaction)
	assert.Equal(fixture.SerializedHex, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
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
