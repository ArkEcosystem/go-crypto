// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

func GetTransactionFixtureWithPassphrase(transactionType byte) string {
	data, _ := ioutil.ReadFile(fmt.Sprintf("./fixtures/Transactions/type-%v/passphrase.json", transactionType))

	return string(data)
}

func GetTransactionFixtureWithSecondPassphrase(transactionType byte) string {
	data, _ := ioutil.ReadFile(fmt.Sprintf("./fixtures/Transactions/type-%v/second-passphrase.json", transactionType))

	return string(data)
}

func GetIdentityFixture() TestingIdentityFixture {
	data, _ := ioutil.ReadFile("./fixtures/identity.json")

	var fixture TestingIdentityFixture
	json.Unmarshal([]byte(data), &fixture)

	return fixture
}
