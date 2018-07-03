// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"crypto/sha256"
)

/*
 Usage
 ===============================================================================
 crypto.SignMessage("Hello World", "passphrase")
*/
func SignMessage(message string, secret string) (*Message, error) {
	privateKey, err := PrivateKeyFromSecret(secret)

	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	_, err = hash.Write([]byte(message))

	if err != nil {
		return nil, err
	}

	signature, err := privateKey.Sign(hash.Sum(nil))

	if err != nil {
		return nil, err
	}

	return &Message{
		PublicKey: HexEncode(privateKey.PublicKey.Serialise()),
		Signature: HexEncode(signature),
		Message:   message,
	}, nil
}

/*
 Usage
 ===============================================================================
 message, _ := crypto.SignMessage("Hello World", "passphrase")
 verified, _ := crypto.VerifyMessage(message)
*/
func VerifyMessage(message *Message) (bool, error) {
	publicKey, _ := PublicKeyFromBytes(HexDecode(message.PublicKey))

	hash := sha256.New()
	_, err := hash.Write([]byte(message.Message))

	if err != nil {
		return false, err
	}

	verified, _ := publicKey.Verify(HexDecode(message.Signature), hash.Sum(nil))

	return verified, nil
}
