package crypto

import (
	"encoding/hex"
	"errors"
	"strings"
)

const AddressByteLength = 20

var ErrInvalidAddress = errors.New("invalid address format")

func AddressFromPassphrase(passphrase string) (string, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return "", err
	}
	return privateKey.ToAddress(), nil
}

func AddressFromPublicKey(publicKeyHex string) (string, error) {
	publicKey, err := PublicKeyFromHex(publicKeyHex)
	if err != nil {
		return "", err
	}
	return publicKey.ToAddress(), nil
}

func AddressFromPrivateKey(privateKeyHex string) (string, error) {
	privateKey, err := PrivateKeyFromHex(privateKeyHex)
	if err != nil {
		return "", err
	}
	return privateKey.ToAddress(), nil
}

func AddressToBytes(address string) ([]byte, error) {
	if !strings.HasPrefix(address, "0x") || len(address) != 2+AddressByteLength*2 {
		return nil, ErrInvalidAddress
	}

	addressBytes, err := hex.DecodeString(address[2:])
	if err != nil {
		return nil, ErrInvalidAddress
	}

	return addressBytes, nil
}

func AddressFromBytes(addressBytes []byte) string {
	return "0x" + EIP55Checksum(hex.EncodeToString(addressBytes))
}

func ValidateAddress(address string) (bool, error) {
	_, err := AddressToBytes(address)
	return err == nil, err
}

func isChecksumValidAddress(address string) bool {
	if _, err := AddressToBytes(address); err != nil {
		return false
	}
	body := address[2:]
	if body == strings.ToLower(body) || body == strings.ToUpper(body) {
		return true
	}
	return body == EIP55Checksum(body)
}
