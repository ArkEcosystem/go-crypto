// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDeserialiseTransfer(t *testing.T) {
	transaction := DeserialiseTransaction("ff0117005e0e690203d3c6889608074b44155ad2e6577c3368e27e6e129c457418eb3e5ed029544e8d80969800000000000a627269616e206375636b00ca9a3b00000000000000001ee03589a014baa6ec16fa87b57f3a1b368ce893ab3044022026f0187f89e3feba6365b9aaabab374ffb57d05ec859922a5c63fbaf9b4bad1d02206ebe4d2dadb909f276e966ebe957fc065b118d808a020b0d886b0e647eb8cab13044022000f058374d9f4a002d7080fc9b306898ecdbec56419d4b41a1fc1cbbc664bc66022010a887491b056c7695dfd072bed04d4ba09cd8472b07a440cd7f5e1e99afd75e")

	assert := assert.New(t)
	assert.Equal(uint64(1000000000), transaction.Amount)
	assert.Equal(uint64(10000000), transaction.Fee)
	assert.Equal("01671092340b44c6892dfd47110e397fde5cd3641c33e7182b8c26acaf6198ed", transaction.Id)
	assert.Equal("DRac35wghMcmUSe5jDMLBDLWkVVjyKZFxK", transaction.RecipientId)
	assert.Equal("03d3c6889608074b44155ad2e6577c3368e27e6e129c457418eb3e5ed029544e8d", transaction.SenderPublicKey)
	assert.Equal("3044022026f0187f89e3feba6365b9aaabab374ffb57d05ec859922a5c63fbaf9b4bad1d02206ebe4d2dadb909f276e966ebe957fc065b118d808a020b0d886b0e647eb8cab1", transaction.Signature)
	assert.Equal("3044022000f058374d9f4a002d7080fc9b306898ecdbec56419d4b41a1fc1cbbc664bc66022010a887491b056c7695dfd072bed04d4ba09cd8472b07a440cd7f5e1e99afd75e", transaction.SignSignature)
	assert.Equal(uint32(40439390), transaction.Timestamp)
	assert.Equal(uint8(0), transaction.Type)
	assert.Equal("brian cuck", transaction.VendorField)
	assert.Equal(uint8(23), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)
}

func TestDeserialiseSecondSignatureRegistration(t *testing.T) {
	transaction := DeserialiseTransaction("ff011e01e3b14a0003a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de9330065cd1d00000000000292d580f200d041861d78b3de5ff31c6665b7a092ac3890d9132593beb9aa85133045022100e4fe1f3fb2845ad5f6ab377f247ffb797661d7516626bdc1d2f0f73eca582b4d02200ada103bdbff439d57c7aaa266f30ce74ff4385f0c77a486070033061b71650c")

	assert := assert.New(t)
	assert.Equal(uint64(0), transaction.Amount)
	assert.Equal("0292d580f200d041861d78b3de5ff31c6665b7a092ac3890d9132593beb9aa8513", transaction.Asset.Signature.PublicKey)
	assert.Equal(uint64(500000000), transaction.Fee)
	assert.Equal("62c36be3e5176771a476d813f64082a8f4e3861c0356438bdf1cc91eebcc9b0d", transaction.Id)
	assert.Equal("D7seWn8JLVwX4nHd9hh2Lf7gvZNiRJ7qLk", transaction.RecipientId)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal("03a02b9d5fdd1307c2ee4652ba54d492d1fd11a7d1bb3f3a44c4a05e79f19de933", transaction.SenderPublicKey)
	assert.Equal("3045022100e4fe1f3fb2845ad5f6ab377f247ffb797661d7516626bdc1d2f0f73eca582b4d02200ada103bdbff439d57c7aaa266f30ce74ff4385f0c77a486070033061b71650c", transaction.Signature)
	assert.Equal(uint32(4895203), transaction.Timestamp)
	assert.Equal(uint8(1), transaction.Type)
	assert.Equal(uint8(1), transaction.Version)
}

func TestDeserialiseDelegateRegistration(t *testing.T) {
	transaction := DeserialiseTransaction("ff011e020000000003e5b39a83e6c7c952c5908089d4524bb8dda93acc2b2b953247e43dc4fe9aa3d10000000000000000000967656e657369735f313045022100e3e38811778023e6f17fefd447f179d45ab92c398c7cfb1e34e2f6e1b167c95a022070c36439ecec0fc3c43850070f29515910435d389e059579878d61b5ff2ea337")

	assert := assert.New(t)
	assert.Equal(uint64(0), transaction.Amount)
	assert.Equal("genesis_1", transaction.Asset.Delegate.Username)
	assert.Equal(uint64(0), transaction.Fee)
	assert.Equal("eb0146ac79afc228f0474a5ae1c4771970ae7880450b998c401029f522cd8a21", transaction.Id)
	assert.Equal("03e5b39a83e6c7c952c5908089d4524bb8dda93acc2b2b953247e43dc4fe9aa3d1", transaction.SenderPublicKey)
	assert.Equal("3045022100e3e38811778023e6f17fefd447f179d45ab92c398c7cfb1e34e2f6e1b167c95a022070c36439ecec0fc3c43850070f29515910435d389e059579878d61b5ff2ea337", transaction.Signature)
	assert.Equal(uint32(0), transaction.Timestamp)
	assert.Equal(uint8(2), transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)
}

func TestDeserialiseVote(t *testing.T) {
	transaction := DeserialiseTransaction("ff011e03d75d42000374e9a97611540a9ce4812b0980e62d3c5141ea964c2cab051f14a78284570dcd00e1f5050000000000010102dcb94d73fb54e775f734762d26975d57f18980314f3b67bc52beb393893bc7063045022100af1e5d6f3c9eff8699192ad1b827e7cf7c60040bd2f704360a1f1fbadf6bc1cf022048238b7175369861436d895adaeeeb31ceb453e543dbf20218a4a5b688650482")

	assert := assert.New(t)
	assert.Equal(uint64(0), transaction.Amount)
	assert.Equal("+02dcb94d73fb54e775f734762d26975d57f18980314f3b67bc52beb393893bc706", transaction.Asset.Votes[0])
	assert.Equal(uint64(100000000), transaction.Fee)
	assert.Equal("a430dbe34172d205ec251875b14438e58e4bd6cf4efc1ebb3da4c206b002115b", transaction.Id)
	assert.Equal("DRac35wghMcmUSe5jDMLBDLWkVVjyKZFxK", transaction.RecipientId)
	assert.Equal("0374e9a97611540a9ce4812b0980e62d3c5141ea964c2cab051f14a78284570dcd", transaction.SenderPublicKey)
	assert.Equal("3045022100af1e5d6f3c9eff8699192ad1b827e7cf7c60040bd2f704360a1f1fbadf6bc1cf022048238b7175369861436d895adaeeeb31ceb453e543dbf20218a4a5b688650482", transaction.Signature)
	assert.Equal(uint32(4349399), transaction.Timestamp)
	assert.Equal(uint8(3), transaction.Type)
	assert.Equal(uint8(30), transaction.Network)
	assert.Equal(uint8(1), transaction.Version)
}

func TestDeserialiseMultiSignatureRegistration(t *testing.T) {
	transaction := DeserialiseTransaction("ff011704724c9a00036928c98ee53a1f52ed01dd87db10ffe1980eb47cd7c0a7d688321f47b5d7d76000943577000000000002031803543c6cc3545be6bac09c82721973a052c690658283472e88f24d14739f75acc80276dc5b8706a85ca9fdc46e571ac84e52fbb48e13ec7a165a80731b44ae89f1fc02e8d5d17eb17bbc8d7bf1001d29a2d25d1249b7bb7a5b7ad8b7422063091f4b3130440220324d89c5792e4a54ae70b4f1e27e2f87a8b7169cc6f2f7b2c83dba894960f987022053b8d0ae23ff9d1769364db7b6fd03216d93753c82a711c3558045e787bc01a5304402201fcd54a9ac9c0269b8cec213566ddf43207798e2cf9ca1ce3c5d315d66321c6902201aa94c4ed3e5e479a12220aa886b259e488eb89b697c711f91e8c03b9620e0b1ff304502210097f17c8eecf36f86a967cc52a83fa661e4ffc70cc4ea08df58673669406d424c0220798f5710897b75dda42f6548f841afbe4ed1fa262097112cf5a1b3f7dade60e4304402201a4a4c718bfdc699bbb891b2e89be018027d2dcd10640b5ddf07802424dab78e02204ec7c7d505d2158c3b51fdd3843d16aecd2eaaa4c6c7a555ef123c5e59fd41fb304402207e660489bced5ce80c33d45c86781b63898775ab4a231bb48780f97b40073a63022026f0cefd0d83022d822522ab4366a82e3b89085c328817919939f2efeabd913d")

	assert := assert.New(t)
	assert.Equal(uint64(0), transaction.Amount)
	assert.Equal("+03543c6cc3545be6bac09c82721973a052c690658283472e88f24d14739f75acc8", transaction.Asset.MultiSignature.Keysgroup[0])
	assert.Equal("+0276dc5b8706a85ca9fdc46e571ac84e52fbb48e13ec7a165a80731b44ae89f1fc", transaction.Asset.MultiSignature.Keysgroup[1])
	assert.Equal("+02e8d5d17eb17bbc8d7bf1001d29a2d25d1249b7bb7a5b7ad8b7422063091f4b31", transaction.Asset.MultiSignature.Keysgroup[2])
	assert.Equal(uint8(24), transaction.Asset.MultiSignature.Lifetime)
	assert.Equal(uint8(2), transaction.Asset.MultiSignature.Min)
	assert.Equal(uint64(2000000000), transaction.Fee)
	assert.Equal("cbd6862966bb1b03ba742397b7e5a88d6eefb393a362ead0d605723b840db2af", transaction.Id)
	assert.Equal(uint8(23), transaction.Network)
	assert.Equal("036928c98ee53a1f52ed01dd87db10ffe1980eb47cd7c0a7d688321f47b5d7d760", transaction.SenderPublicKey)
	assert.Equal("30440220324d89c5792e4a54ae70b4f1e27e2f87a8b7169cc6f2f7b2c83dba894960f987022053b8d0ae23ff9d1769364db7b6fd03216d93753c82a711c3558045e787bc01a5", transaction.Signature)
	assert.Equal("304502210097f17c8eecf36f86a967cc52a83fa661e4ffc70cc4ea08df58673669406d424c0220798f5710897b75dda42f6548f841afbe4ed1fa262097112cf5a1b3f7dade60e4", transaction.Signatures[0])
	assert.Equal("304402201a4a4c718bfdc699bbb891b2e89be018027d2dcd10640b5ddf07802424dab78e02204ec7c7d505d2158c3b51fdd3843d16aecd2eaaa4c6c7a555ef123c5e59fd41fb", transaction.Signatures[1])
	assert.Equal("304402207e660489bced5ce80c33d45c86781b63898775ab4a231bb48780f97b40073a63022026f0cefd0d83022d822522ab4366a82e3b89085c328817919939f2efeabd913d", transaction.Signatures[2])
	assert.Equal("304402201fcd54a9ac9c0269b8cec213566ddf43207798e2cf9ca1ce3c5d315d66321c6902201aa94c4ed3e5e479a12220aa886b259e488eb89b697c711f91e8c03b9620e0b1", transaction.SignSignature)
	assert.Equal(uint32(10112114), transaction.Timestamp)
	assert.Equal(uint8(4), transaction.Type)
	assert.Equal(uint8(1), transaction.Version)
}

func TestDeserialiseIpfs(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserialiseTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}

func TestDeserialiseTimelockTransfer(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserialiseTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}

func TestDeserialiseMultiPayment(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserialiseTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}

func TestDeserialiseDelegateResignation(t *testing.T) {
	t.Skip("skipping test!")

	// transaction := DeserialiseTransaction("...")

	// assert := assert.New(t)
	// assert.Equal(transaction.Id, id)
	// assert.Equal(transaction.Version, version)
	// assert.Equal(transaction.Network, network)
	// assert.Equal(transaction.Type, type)
	// assert.Equal(transaction.SenderPublicKey, senderPublicKey)
}
