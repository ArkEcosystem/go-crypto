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
	"fmt"
	"log"

	"github.com/fatih/structs"
)

func (transaction *Transaction) GetId() string {
	return fmt.Sprintf("%x", sha256.Sum256(transaction.serialize(true, true, true)))
}

func (transaction *Transaction) Sign(passphrase string) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		log.Printf("Error deriving private key from passphrase: %v\n", err)
		return
	}

	transaction.SenderPublicKey = HexEncode(privateKey.PublicKey.Serialize())
	
	hash := sha256.Sum256(transaction.serialize(false, false, false))

	signature, err := privateKey.Sign(hash[:])
	if err == nil {
		transaction.Signature = HexEncode(signature)
	} else {
		log.Printf("Error signing transaction: %v\n", err)
	}
}

func (transaction *Transaction) SignMulti(signerIndex int, passphrase string) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		log.Printf("Error deriving private key from passphrase: %v\n", err)
		return
	}

	hash := sha256.Sum256(transaction.serialize(false, false, false))

	signature, err := privateKey.SignMulti(hash[:], signerIndex)
	if err == nil {
		transaction.Signatures = append(transaction.Signatures, HexEncode(signature))
	} else {
		log.Printf("Error signing multi-signature transaction: %v\n", err)
	}
}

func (transaction *Transaction) SecondSign(passphrase string) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		log.Printf("Error deriving private key from passphrase: %v\n", err)
		return
	}

	hash := sha256.Sum256(transaction.serialize(true, false, false))

	signature, err := privateKey.SecondSign(hash[:])
	if err == nil {
		transaction.SecondSignature = HexEncode(signature)
	} else {
		log.Printf("Error creating second signature: %v\n", err)
	}
}

func (transaction *Transaction) VerifyMultiSignature(multiSignatureAsset *MultiSignatureRegistrationAsset) (bool, error) {
	hash := sha256.Sum256(transaction.serialize(false, false, false))

	publicKeyIndexes := make(map[int]bool)
	numVerified := 0

	for i := 0; i < len(transaction.Signatures); i++ {
		if len(transaction.Signatures[i]) < 2 {
			return false, fmt.Errorf("VerifyMultiSignature: signature %d too short to contain index", i)
		}
		publicKeyIndex := int(HexDecode(transaction.Signatures[i][:2])[0])
		signature := HexDecode(transaction.Signatures[i][2:])

		if publicKeyIndexes[publicKeyIndex] {
			return false, fmt.Errorf("VerifyMultiSignature: duplicate signer index: %d", publicKeyIndex)
		}

		if publicKeyIndex >= len(multiSignatureAsset.PublicKeys) {
			return false, fmt.Errorf(
				"VerifyMultiSignature: signer index too large: %d, total of %d "+
					"signers have been registered",
				publicKeyIndex, len(multiSignatureAsset.PublicKeys))
		}

		publicKeyIndexes[publicKeyIndex] = true

		publicKey, err := PublicKeyFromBytes(HexDecode(multiSignatureAsset.PublicKeys[publicKeyIndex]))
		if err != nil {
			return false, err
		}

		verified, err := publicKey.Verify(signature, hash[:])
		if err != nil {
			return false, fmt.Errorf("VerifyMultiSignature: error verifying signature %d: %v", i, err)
		}

		if verified {
			numVerified++
		}

		if numVerified >= int(multiSignatureAsset.Min) {
			return true, nil
		}

		if len(transaction.Signatures)-(i+1-numVerified) < int(multiSignatureAsset.Min) {
			return false, fmt.Errorf(
				"VerifyMultiSignature: less than the minimum %d signatures verified successfully",
				multiSignatureAsset.Min)
		}
	}

	return false, fmt.Errorf(
		"VerifyMultiSignature: less than the minimum %d signatures verified successfully (checked all)",
		multiSignatureAsset.Min)
}

func (transaction *Transaction) Verify(multiSignatureAsset ...*MultiSignatureRegistrationAsset) (bool, error) {
	if len(multiSignatureAsset) == 1 && multiSignatureAsset[0].Min > 0 {
		return transaction.VerifyMultiSignature(multiSignatureAsset[0])
	}

	publicKey, err := PublicKeyFromBytes(HexDecode(transaction.SenderPublicKey))
	if err != nil {
		return false, err
	}

	hash := sha256.Sum256(transaction.serialize(false, false, true))

	return publicKey.Verify(HexDecode(transaction.Signature), hash[:])
}

func (transaction *Transaction) SecondVerify(secondPublicKey *PublicKey) (bool, error) {
	hash := sha256.Sum256(transaction.serialize(true, false, false))

	return secondPublicKey.Verify(HexDecode(transaction.SecondSignature), hash[:])
}

func (transaction *Transaction) ParseSignatures(sigOffset int) *Transaction {
	signatures := transaction.Serialized[sigOffset:]
	signaturesLen := len(signatures)

	if signaturesLen == 0 {
		transaction.Signature = ""
		return transaction
	}

	return transaction.ParseSignaturesSchnorr(signatures)
}

func (transaction *Transaction) ParseSignaturesSchnorr(signatures []byte) *Transaction {
	const schnorrSignatureLen = 64

	signaturesLen := len(signatures)
	o := 0

	canReadNonMultiSignature := func() bool {
		remaining := signaturesLen - o
		return remaining >= schnorrSignatureLen && remaining%65 != 0
	}

	readSchnorrSignature := func() string {
		sig := HexEncode(signatures[o : o+schnorrSignatureLen])
		o += schnorrSignatureLen
		return sig
	}

	if canReadNonMultiSignature() {
		transaction.Signature = readSchnorrSignature()
	}

	if canReadNonMultiSignature() {
		transaction.SecondSignature = readSchnorrSignature()
	}

	if signaturesLen-o == 0 {
		return transaction
	}

	if (signaturesLen-o)%65 != 0 {
		log.Fatalf("Cannot parse Schnorr signatures: remaining bytes not multiple of 65: %d", signaturesLen-o)
	}

	count := (signaturesLen - o) / 65

	for i := 0; i < count; i++ {
		signaturePlusPrefix := HexEncode(signatures[o : o+1+schnorrSignatureLen])
		o += 1 + schnorrSignatureLen

		transaction.Signatures = append(transaction.Signatures, signaturePlusPrefix)
	}

	return transaction
}

func (transaction *Transaction) ToMap() map[string]interface{} {
	return structs.Map(transaction)
}

func (transaction *Transaction) ToJson() (string, error) {
	jason, err := json.Marshal(transaction)

	if err != nil {
		return "", err
	}

	return string(jason), nil
}
