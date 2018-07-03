// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSerialiseTransfer(t *testing.T) {
	serialised := "ff0117005e0e690203d3c6889608074b44155ad2e6577c3368e27e6e129c457418eb3e5ed029544e8d80969800000000000a627269616e206375636b00ca9a3b00000000000000001ee03589a014baa6ec16fa87b57f3a1b368ce893ab3044022026f0187f89e3feba6365b9aaabab374ffb57d05ec859922a5c63fbaf9b4bad1d02206ebe4d2dadb909f276e966ebe957fc065b118d808a020b0d886b0e647eb8cab13044022000f058374d9f4a002d7080fc9b306898ecdbec56419d4b41a1fc1cbbc664bc66022010a887491b056c7695dfd072bed04d4ba09cd8472b07a440cd7f5e1e99afd75e"
	transaction := DeserialiseTransaction(serialised)

	assert := assert.New(t)
	assert.Equal(serialised, SerialiseTransaction(transaction))
}

func TestSerialiseSecondSignatureRegistration(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseDelegateRegistration(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseVote(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseMultiSignatureRegistration(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseIpfs(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseTimelockTransfer(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseMultiPayment(t *testing.T) {
	t.Skip("skipping test!")
}

func TestSerialiseDelegateResignation(t *testing.T) {
	t.Skip("skipping test!")
}
