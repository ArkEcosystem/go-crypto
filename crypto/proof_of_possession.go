package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tyler-smith/go-bip39"
)

const popDST = "MAINSAIL_BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

var ErrInvalidProofOfPossession = errors.New("crypto: invalid proof of possession")

type ProofOfPossessionResult struct {
	PK  []byte
	POP []byte
}

func DeriveBlsPrivateKey(passphrase string) []byte {
	return popDeriveChildSk(passphrase).Serialize()
}

func DeriveBlsPublicKey(passphrase string) string {
	sk := popDeriveChildSk(passphrase)
	pk := new(blst.P1Affine).From(sk)
	return hex.EncodeToString(pk.Compress())
}

func BuildProofOfPossession(secretKeyBytes []byte, registrantAddress string) (*ProofOfPossessionResult, error) {
	if !isChecksumValidAddress(registrantAddress) {
		return nil, fmt.Errorf("%w: invalid registrant address %q", ErrInvalidProofOfPossession, registrantAddress)
	}
	registrantBytes, _ := AddressToBytes(registrantAddress)

	sk := new(blst.SecretKey)
	if sk.Deserialize(secretKeyBytes) == nil {
		return nil, errors.New("invalid secret key bytes")
	}
	pk := new(blst.P1Affine).From(sk)
	pkBytes := pk.Compress()

	chainId := abiPadWordLeft(big.NewInt(int64(GetNetwork().ChainId)).Bytes())
	message := append(append(chainId, registrantBytes...), pkBytes...)

	sig := new(blst.P2Affine).Sign(sk, message, []byte(popDST))
	return &ProofOfPossessionResult{PK: pkBytes, POP: sig.Compress()}, nil
}

func FromMnemonic(passphrase string, registrantAddress string) (*ProofOfPossessionResult, error) {
	return BuildProofOfPossession(DeriveBlsPrivateKey(passphrase), registrantAddress)
}

// Ideographic spaces (U+3000, used to separate words in the Japanese BIP-39
// wordlist) are normalized to U+0020 before hashing — go-bip39's NewSeed
// does no normalization of its own, so without this, Japanese mnemonics
// derive a different seed than every other reference BIP-39 implementation.
func popDeriveChildSk(passphrase string) *blst.SecretKey {
	normalized := strings.ReplaceAll(passphrase, "\u3000", " ")
	seed := bip39.NewSeed(normalized, "")
	return blst.KeyGen(seed).DeriveChildEip2333(0)
}
