package crypto

import (
	"encoding/json"
	"errors"

	"github.com/fatih/structs"
	"golang.org/x/crypto/sha3"
)

var (
	ErrTransactionNotSigned               = errors.New("crypto: transaction has no senderPublicKey to verify against")
	ErrLegacySecondSignatureBeforeSigning = errors.New("crypto: transaction must be signed before adding a legacy second signature")
)

// legacySecondSignatureDomain is 0x8f ‖ "MAINSAIL_LSS_V1", prefixed to the
// transaction hash before the second key signs it.
var legacySecondSignatureDomain = append([]byte{0x8f}, []byte("MAINSAIL_LSS_V1")...)

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
// yet); once signed, it becomes the transaction's final hash/ID. The hash
// never covers the legacy second signature.
func (transaction *Transaction) GetHash() (string, error) {
	serialized, err := transaction.serialize(false, true)
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

	return transaction.signWithPrivateKey(privateKey)
}

func (transaction *Transaction) signWithPrivateKey(privateKey *PrivateKey) error {
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

// LegacySecondSign signs the transaction with the wallet's legacy second
// passphrase. The second key signs keccak256(0x8f ‖ "MAINSAIL_LSS_V1" ‖ hash),
// where hash is the hash of the already signed transaction, so Sign must be
// called first.
func (transaction *Transaction) LegacySecondSign(secondPassphrase string) error {
	privateKey, err := PrivateKeyFromPassphrase(secondPassphrase)
	if err != nil {
		return err
	}

	return transaction.legacySecondSignWithPrivateKey(privateKey)
}

func (transaction *Transaction) legacySecondSignWithPrivateKey(privateKey *PrivateKey) error {
	if len(transaction.R) == 0 || len(transaction.S) == 0 {
		return ErrLegacySecondSignatureBeforeSigning
	}

	signed, err := transaction.serialize(false, true)
	if err != nil {
		return err
	}

	message := append(append([]byte{}, legacySecondSignatureDomain...), keccak256(signed)...)
	sig := privateKey.Sign(keccak256(message))

	legacySecondSignature := append(append([]byte{}, sig.R...), sig.S...)
	transaction.LegacySecondSignature = append(legacySecondSignature, byte(sig.RecoveryId))

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
