// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
    "crypto/sha256"
    "encoding/hex"
)

type Message struct {
    PublicKey string `json:"publickey"`
    Signature string `json:"signature"`
    Message   string `json:"message"`
}

/*
 Usage
 ===============================================================================
 crypto.SignMessage("Hello World", "passphrase")
 */
func SignMessage(message string, secret string) (*Message, error) {
    privateKey, err := PrivateKeyFromSecret(secret, NETWORKS_DEVNET)

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
        PublicKey: hex.EncodeToString(privateKey.PublicKey.Serialise()),
        Signature: hex.EncodeToString(signature),
        Message: message,
    }, nil
}

/*
 Usage
 ===============================================================================
 message, _ := crypto.SignMessage("Hello World", "passphrase")
 verified, _ := crypto.VerifyMessage(message)
 */
func VerifyMessage(message *Message) (bool, error) {
    publicKey, _ := PublicKeyFromBytes(hexDecode(message.PublicKey), NETWORKS_DEVNET)

    hash := sha256.New()
    _, err := hash.Write([]byte(message.Message))

    if err != nil {
        return false, err
    }

    verified, _ := publicKey.Verify(hexDecode(message.Signature), hash.Sum(nil))

    return verified, nil
}
