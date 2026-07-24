package crypto

import (
	"encoding/json"
	"strconv"

	"github.com/fatih/structs"
)

const personalMessagePrefix = "\x19Ethereum Signed Message:\n"

func personalSignHash(message string) []byte {
	prefixed := personalMessagePrefix + strconv.Itoa(len(message)) + message
	return keccak256([]byte(prefixed))
}

func SignMessage(message string, passphrase string) (*Message, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return nil, err
	}

	sig := privateKey.Sign(personalSignHash(message))

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

	return publicKey.Verify(personalSignHash(message.Message), sig)
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
