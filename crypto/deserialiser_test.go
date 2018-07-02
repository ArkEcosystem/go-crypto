// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
    "testing"
    "github.com/stretchr/testify/assert"
)

func TestDeserialiseTransfer(t *testing.T) {
    transaction := DeserialiseTransaction("ff0117005e0e690203d3c6889608074b44155ad2e6577c3368e27e6e129c457418eb3e5ed029544e8d80969800000000000a627269616e206375636b00ca9a3b00000000000000001ee03589a014baa6ec16fa87b57f3a1b368ce893ab3044022026f0187f89e3feba6365b9aaabab374ffb57d05ec859922a5c63fbaf9b4bad1d02206ebe4d2dadb909f276e966ebe957fc065b118d808a020b0d886b0e647eb8cab13044022000f058374d9f4a002d7080fc9b306898ecdbec56419d4b41a1fc1cbbc664bc66022010a887491b056c7695dfd072bed04d4ba09cd8472b07a440cd7f5e1e99afd75e")

    assert := assert.New(t)
    assert.Equal(transaction.Id, "01671092340b44c6892dfd47110e397fde5cd3641c33e7182b8c26acaf6198ed")
    assert.Equal(transaction.Type, uint8(0))
    assert.Equal(transaction.Timestamp, uint32(40439390))
    assert.Equal(transaction.Amount, uint64(1000000000))
    assert.Equal(transaction.Fee, uint64(10000000))
    assert.Equal(transaction.VendorField, "brian cuck")
    assert.Equal(transaction.RecipientId, "DRac35wghMcmUSe5jDMLBDLWkVVjyKZFxK")
    assert.Equal(transaction.SenderPublicKey, "03d3c6889608074b44155ad2e6577c3368e27e6e129c457418eb3e5ed029544e8d")
    assert.Equal(transaction.Signature, "3044022026f0187f89e3feba6365b9aaabab374ffb57d05ec859922a5c63fbaf9b4bad1d02206ebe4d2dadb909f276e966ebe957fc065b118d808a020b0d886b0e647eb8cab1")
    assert.Equal(transaction.SignSignature, "3044022000f058374d9f4a002d7080fc9b306898ecdbec56419d4b41a1fc1cbbc664bc66022010a887491b056c7695dfd072bed04d4ba09cd8472b07a440cd7f5e1e99afd75e")
}
