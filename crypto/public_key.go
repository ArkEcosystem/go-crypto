package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func PublicKeyFromPassphrase(passphrase string) (*PublicKey, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return nil, err
	}
	return privateKey.PublicKey, nil
}

func PublicKeyFromHex(publicKeyHex string) (*PublicKey, error) {
	publicKey, err := PublicKeyFromBytes(HexDecode(publicKeyHex))
	if err != nil {
		return nil, err
	}
	return publicKey, nil
}

func PublicKeyFromBytes(bytes []byte) (*PublicKey, error) {
	publicKey, err := secp256k1.ParsePubKey(bytes)
	if err != nil {
		return nil, err
	}
	isCompressed := false
	if len(bytes) == secp256k1.PubKeyBytesLenCompressed {
		isCompressed = true
	}
	return &PublicKey{
		PublicKey:    publicKey,
		isCompressed: isCompressed,
		Network:      GetNetwork(),
	}, nil
}

////////////////////////////////////////////////////////////////////////////////
// ADDRESS COMPUTATION /////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func (publicKey *PublicKey) ToHex() string {
	return HexEncode(publicKey.Serialize())
}

func (publicKey *PublicKey) ToAddress() string {
	pubBytes := publicKey.PublicKey.SerializeUncompressed()
	pubBytes = pubBytes[1:]
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubBytes)
	hashed := hash.Sum(nil)
	addressBytes := hashed[12:]
	address := hex.EncodeToString(addressBytes)
	return "0x" + EIP55Checksum(address)
}

func EIP55Checksum(address string) string {
	addressHash := sha3.NewLegacyKeccak256()
	addressHash.Write([]byte(strings.ToLower(address)))
	hash := hex.EncodeToString(addressHash.Sum(nil))
	result := ""
	for i := 0; i < len(address); i++ {
		if address[i] >= '0' && address[i] <= '9' {
			result += string(address[i])
		} else {
			if hash[i] >= '8' {
				result += string(strings.ToUpper(string(address[i])))
			} else {
				result += string(strings.ToLower(string(address[i])))
			}
		}
	}
	return result
}

func (publicKey *PublicKey) Serialize() []byte {
	if publicKey.isCompressed {
		return publicKey.SerializeCompressed()
	}
	return publicKey.SerializeUncompressed()
}

func (publicKey *PublicKey) SerializeCompressed() []byte {
	return publicKey.PublicKey.SerializeCompressed()
}

func (publicKey *PublicKey) SerializeUncompressed() []byte {
	return publicKey.PublicKey.SerializeUncompressed()
}

// isCompressed must match how the signer's key was represented when signing
// (PrivateKey.Sign uses the signing key's own isCompressed value).
func RecoverPublicKey(hash []byte, sig *EcdsaSignature, isCompressed bool) (*PublicKey, error) {
	if len(sig.R) != ecdsaCurveByteLength || len(sig.S) != ecdsaCurveByteLength {
		return nil, fmt.Errorf("RecoverPublicKey: R and S must each be %d bytes", ecdsaCurveByteLength)
	}

	header := byte(27 + sig.RecoveryId)
	if isCompressed {
		header += 4
	}

	compact := make([]byte, 0, 1+2*ecdsaCurveByteLength)
	compact = append(compact, header)
	compact = append(compact, sig.R...)
	compact = append(compact, sig.S...)

	pubKey, _, err := ecdsa.RecoverCompact(compact, hash)
	if err != nil {
		return nil, fmt.Errorf("RecoverPublicKey: %v", err)
	}

	return &PublicKey{
		PublicKey:    pubKey,
		isCompressed: isCompressed,
		Network:      GetNetwork(),
	}, nil
}

// Verify recovers the actual signer from sig and compares it to publicKey.
func (publicKey *PublicKey) Verify(hash []byte, sig *EcdsaSignature) (bool, error) {
	recovered, err := RecoverPublicKey(hash, sig, publicKey.isCompressed)
	if err != nil {
		return false, err
	}

	return recovered.PublicKey.IsEqual(publicKey.PublicKey), nil
}
