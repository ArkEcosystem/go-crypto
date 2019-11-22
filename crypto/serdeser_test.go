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
	"testing"

	"github.com/stretchr/testify/assert"
)

func commonSerDeserTest(t *testing.T, transactionType string, file string) {
	fixtureJson := []byte(GetTransactionFixture(transactionType, file))

	var fixture TestingFixture

	err := json.Unmarshal(fixtureJson, &fixture)
	if err != nil {
		log.Fatal("Cannot parse fixture JSON ", transactionType, "/", file, ": ", err)
	}

	fixture.Transaction.Serialized = HexDecode(fixture.SerializedHex)

	transaction := DeserializeTransaction(fixture.SerializedHex)

	assert := assert.New(t)

	assert.Equal(fixture.Transaction, *transaction)
	assert.Equal(fixture.SerializedHex, HexEncode(transaction.serialize(true, true)))
	assert.True(transaction.Verify())
}

func TestSerDeserTransferWithPassphrase(t *testing.T) {
	commonSerDeserTest(t, "transfer", "passphrase-no-vendor-field")
}

func TestSerDeserTransferWithSecondPassphrase(t *testing.T) {
	commonSerDeserTest(t, "transfer", "second-passphrase-no-vendor-field")
}

func TestSerDeserTransferWithPassphraseAndVendorField(t *testing.T) {
	commonSerDeserTest(t, "transfer", "passphrase-with-vendor-field")
}

func TestSerDeserTransferWithSecondPassphraseAndVendorField(t *testing.T) {
	commonSerDeserTest(t, "transfer", "second-passphrase-with-vendor-field")
}

func TestSerDeserSecondSignatureRegistrationWithPassphrase(t *testing.T) {
	commonSerDeserTest(t, "second_signature_registration", "passphrase-no-vendor-field")
}

func TestSerDeserDelegateRegistrationWithPassphrase(t *testing.T) {
	commonSerDeserTest(t, "delegate_registration", "passphrase-no-vendor-field")
}

func TestSerDeserDelegateRegistrationWithSecondPassphrase(t *testing.T) {
	commonSerDeserTest(t, "delegate_registration", "second-passphrase-no-vendor-field")
}

func TestSerDeserVoteWithPassphrase(t *testing.T) {
	commonSerDeserTest(t, "vote", "passphrase-no-vendor-field")
}

func TestSerDeserVoteWithSecondPassphrase(t *testing.T) {
	commonSerDeserTest(t, "vote", "second-passphrase-no-vendor-field")
}

/*
func TestSerDeserMultiSignatureRegistrationWithSecondPassphrase(t *testing.T) {
	commonSerDeserTest(t, "multi_signature_registration", "second-passphrase-no-vendor-field")
}
*/

func TestSerDeserIpfs(t *testing.T) {
	commonSerDeserTest(t, "vote", "passphrase-no-vendor-field")
}

func TestSerDeserMultiPayment(t *testing.T) {
	commonSerDeserTest(t, "multi_payment", "passphrase-no-vendor-field")
}

func TestSerDeserDelegateResignation(t *testing.T) {
	commonSerDeserTest(t, "delegate_resignation", "passphrase-no-vendor-field")
}

func TestSerDeserHtlcLock(t *testing.T) {
	commonSerDeserTest(t, "htlc_lock", "passphrase-no-vendor-field")
}
