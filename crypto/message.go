// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"crypto/sha256"
	"encoding/json"

	"github.com/fatih/structs"
)

// SignMessage signs an arbitrary message with the private key derived from
// passphrase.
//
// NOTE: this still hashes the message with plain sha256, carried over
// unchanged from before the Mainsail migration. Ethereum's personal_sign
// convention (keccak256("\x19Ethereum Signed Message:\n" + len(message) +
// message)) is a separate, not-yet-made design change.
func SignMessage(message string, passphrase string) (*Message, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(message))
	sig := privateKey.Sign(hash[:])

	return &Message{
		PublicKey: HexEncode(privateKey.PublicKey.Serialize()),
		Signature: HexEncode(sig.Bytes()),
		Message:   message,
	}, nil
}

func (message *Message) Verify() (bool, error) {
	publicKey, err := PublicKeyFromBytes(HexDecode(message.PublicKey))
	if err != nil {
		return false, err
	}

	sig, err := EcdsaSignatureFromBytes(HexDecode(message.Signature))
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256([]byte(message.Message))

	return publicKey.Verify(hash[:], sig)
}

func (message *Message) ToMap() map[string]interface{} {
	return structs.Map(message)
}

func (message *Message) ToJson() (string, error) {
	jason, err := json.Marshal(message)

	if err != nil {
		return "", err
	}

	return string(jason), nil
}
