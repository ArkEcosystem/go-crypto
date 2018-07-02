// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
    "log"
    "./base58"
    "crypto/sha256"
    "github.com/btcsuite/btcd/btcec"
    "golang.org/x/crypto/ripemd160"
)

var (
    secp256k1 = btcec.S256()
)

type PublicKey struct {
    *btcec.PublicKey
    isCompressed bool
    network      *Network
}

type PrivateKey struct {
    *btcec.PrivateKey
    PublicKey *PublicKey
}

////////////////////////////////////////////////////////////////////////////////
// ADDRESS /////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Derive and address from a secret
func AddressFromSecret(secret string, network *Network) string {
    return PrivateKeyFromSecret(secret, network).Address()
}

// Derive and address from a public key
func (publicKey *PublicKey) Address() string {
    ripeHashedBytes := publicKey.AddressBytes()
    ripeHashedBytes = append(ripeHashedBytes, 0x0)
    copy(ripeHashedBytes[1:], ripeHashedBytes[:len(ripeHashedBytes)-1])
    ripeHashedBytes[0] = publicKey.network.Version

    return base58.Encode(ripeHashedBytes)
}

// Derive and address from a private key
func (privateKey *PrivateKey) Address() string {
    return privateKey.PublicKey.Address()
}

// Serialise a public key according to its compression level
func (publicKey *PublicKey) Serialise() []byte {
    if publicKey.isCompressed {
        return publicKey.SerializeCompressed()
    }

    return publicKey.SerializeUncompressed()
}

// Turn an address to its byte representation
func (publicKey *PublicKey) AddressBytes() []byte {
    hash := ripemd160.New()

    if _, err := hash.Write(publicKey.Serialise()[:]); err != nil {
        log.Fatal(err)
    }

    return hash.Sum(nil)
}

func AddressToBytes(address string) ([]byte, error) {
    pb, err := base58.Decode(address)

    if err != nil {
        return nil, err
    }

    return pb[1:], nil
}

func ValidateAddress() {

}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC KEY //////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Derive a public key from the given secret
func PublicKeyFromSecret(secret string, network *Network) *PublicKey {
    return PrivateKeyFromSecret(secret, network).PublicKey
}

// Derive a public key from the given bytes representation
func PublicKeyFromBytes(bytes []byte, network *Network) (*PublicKey, error) {
    publicKey, err := btcec.ParsePubKey(bytes, secp256k1)

    if err != nil {
        return nil, err
    }

    isCompressed := false

    if len(bytes) == btcec.PubKeyBytesLenCompressed {
        isCompressed = true
    }

    return &PublicKey{
        PublicKey:    publicKey,
        isCompressed: isCompressed,
        network:      network,
    }, nil
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE KEY /////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Derive a public key from the given bytes representation
func PrivateKeyFromBytes(bytes []byte, network *Network) *PrivateKey {
    privateKey, publicKey := btcec.PrivKeyFromBytes(secp256k1, bytes)

    return &PrivateKey{
        PrivateKey: privateKey,
        PublicKey: &PublicKey{
            PublicKey:    publicKey,
            isCompressed: true,
            network:      network,
        },
    }
}

// Derive a public key from the given secret
func PrivateKeyFromSecret(secret string, network *Network) *PrivateKey {
    h := sha256.New()
    h.Write([]byte(secret))
    pb := h.Sum(nil)

    return PrivateKeyFromBytes(pb, network)
}

////////////////////////////////////////////////////////////////////////////////
// WIF /////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// Dervie a WIF from the given privat key
func (privateKey *PrivateKey) WIF() string {
    p := privateKey.Serialize()

    if privateKey.PublicKey.isCompressed {
        p = append(p, 0x1)
    }

    p = append(p, 0x0)
    copy(p[1:], p[:len(p)-1])
    p[0] = privateKey.PublicKey.network.Wif

    return base58.Encode(p)
}
