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
	serialised := "ff011e01e3b14a0003a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de9330065cd1d00000000000292d580f200d041861d78b3de5ff31c6665b7a092ac3890d9132593beb9aa85133045022100e4fe1f3fb2845ad5f6ab377f247ffb797661d7516626bdc1d2f0f73eca582b4d02200ada103bdbff439d57c7aaa266f30ce74ff4385f0c77a486070033061b71650c"
	transaction := DeserialiseTransaction(serialised)

	assert := assert.New(t)
	assert.Equal(serialised, SerialiseTransaction(transaction))
}

func TestSerialiseDelegateRegistration(t *testing.T) {
	serialised := "ff011e020000000003e5b39a83e6c7c952c5908089d4524bb8dda93acc2b2b953247e43dc4fe9aa3d10000000000000000000967656e657369735f313045022100e3e38811778023e6f17fefd447f179d45ab92c398c7cfb1e34e2f6e1b167c95a022070c36439ecec0fc3c43850070f29515910435d389e059579878d61b5ff2ea337"
	transaction := DeserialiseTransaction(serialised)

	assert := assert.New(t)
	assert.Equal(serialised, SerialiseTransaction(transaction))
}

func TestSerialiseVote(t *testing.T) {
	serialised := "ff011e03d75d42000374e9a97611540a9ce4812b0980e62d3c5141ea964c2cab051f14a78284570dcd00e1f5050000000000010102dcb94d73fb54e775f734762d26975d57f18980314f3b67bc52beb393893bc7063045022100af1e5d6f3c9eff8699192ad1b827e7cf7c60040bd2f704360a1f1fbadf6bc1cf022048238b7175369861436d895adaeeeb31ceb453e543dbf20218a4a5b688650482"
	transaction := DeserialiseTransaction(serialised)

	assert := assert.New(t)
	assert.Equal(serialised, SerialiseTransaction(transaction))
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
