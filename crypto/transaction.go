// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/json"
	"errors"

	"github.com/fatih/structs"
	"golang.org/x/crypto/sha3"
)

var ErrTransactionNotSigned = errors.New("crypto: transaction has no senderPublicKey to verify against")

func keccak256(data []byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write(data)
	return hash.Sum(nil)
}

// SigningHash is the message a signer signs and a verifier/recoverer checks
// against.
func (transaction *Transaction) SigningHash() ([]byte, error) {
	serialized, err := transaction.Serialize(true)
	if err != nil {
		return nil, err
	}
	return keccak256(serialized), nil
}

// Before signing, GetHash is identical to SigningHash (no v/r/s to embed
// yet); once signed, it becomes the transaction's final hash/ID.
func (transaction *Transaction) GetHash() (string, error) {
	serialized, err := transaction.Serialize(false)
	if err != nil {
		return "", err
	}
	return HexEncode(keccak256(serialized)), nil
}

// Sign derives a private key from passphrase, signs the transaction, and
// populates SenderPublicKey, From, V, R, S, Hash, and Serialized.
func (transaction *Transaction) Sign(passphrase string) error {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return err
	}

	transaction.SenderPublicKey = privateKey.PublicKey.ToHex()
	transaction.From = privateKey.PublicKey.ToAddress()

	signingHash, err := transaction.SigningHash()
	if err != nil {
		return err
	}

	sig := privateKey.Sign(signingHash)
	transaction.V = sig.RecoveryId
	transaction.R = sig.R
	transaction.S = sig.S

	hash, err := transaction.GetHash()
	if err != nil {
		return err
	}
	transaction.Hash = hash

	serialized, err := transaction.Serialize(false)
	if err != nil {
		return err
	}
	transaction.Serialized = serialized

	return nil
}

// RecoverSender recovers the sender's public key and address from the
// transaction's signature and populates SenderPublicKey and From.
//
// isCompressed is hardcoded to true: PrivateKeyFromBytes (the only private
// key construction path in this SDK) always produces a compressed key, so
// every signature this SDK itself produces was made with one.
func (transaction *Transaction) RecoverSender() error {
	signingHash, err := transaction.SigningHash()
	if err != nil {
		return err
	}

	sig := &EcdsaSignature{R: transaction.R, S: transaction.S, RecoveryId: transaction.V}

	publicKey, err := RecoverPublicKey(signingHash, sig, true)
	if err != nil {
		return err
	}

	transaction.SenderPublicKey = publicKey.ToHex()
	transaction.From = publicKey.ToAddress()

	return nil
}

// Verify reports whether the transaction's signature was produced by the
// private key matching its SenderPublicKey.
func (transaction *Transaction) Verify() (bool, error) {
	if transaction.SenderPublicKey == "" {
		return false, ErrTransactionNotSigned
	}

	publicKey, err := PublicKeyFromHex(transaction.SenderPublicKey)
	if err != nil {
		return false, err
	}

	signingHash, err := transaction.SigningHash()
	if err != nil {
		return false, err
	}

	sig := &EcdsaSignature{R: transaction.R, S: transaction.S, RecoveryId: transaction.V}

	return publicKey.Verify(signingHash, sig)
}

func (transaction *Transaction) ToMap() map[string]interface{} {
	return structs.Map(transaction)
}

func (transaction *Transaction) ToJson() (string, error) {
	data, err := json.Marshal(transaction)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
