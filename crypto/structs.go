// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"github.com/btcsuite/btcd/btcec"
)

type Network struct {
	Epoch   string
	Version byte
	Nethash string
	Wif     byte
	WifByte []byte
}

type PrivateKey struct {
	*btcec.PrivateKey
	PublicKey *PublicKey
}

type PublicKey struct {
	*btcec.PublicKey
	isCompressed bool
	network      *Network
}

type TransactionTypes struct {
	Transfer                    uint32
	SecondSignatureRegistration uint32
	DelegateRegistration        uint32
	Vote                        uint32
	MultiSignatureRegistration  uint32
	Ipfs                        uint32
	TimelockTransfer            uint32
	MultiPayment                uint32
	DelegateResignation         uint32
}

type Transaction struct {
	Version               byte              `json:"version,omitempty"`
	Network               byte              `json:"network,omitempty"`
	Type                  byte              `json:"type,omitempty"`
	Timestamp             uint32            `json:"timestamp,omitempty"`
	SenderPublicKey       string            `json:"senderPublicKey,omitempty"`
	SecondSenderPublicKey string            `json:"secondSenderPublicKey,omitempty"`
	Fee                   uint64            `json:"fee,omitempty"`
	Amount                uint64            `json:"amount,omitempty"`
	Expiration            uint32            `json:"expiration,omitempty"`
	RecipientId           string            `json:"recipientId,omitempty"`
	Signature             string            `json:"signature,omitempty"`
	SecondSignature       string            `json:"secondSignature,omitempty"`
	SignSignature         string            `json:"signSignature,omitempty"`
	Signatures            []string          `json:"signatures,omitempty"`
	VendorFieldHex        []byte            `json:"vendorFieldHex,omitempty"`
	VendorField           string            `json:"vendorField,omitempty"`
	Asset                 *TransactionAsset `json:"asset,omitempty"`
	Id                    string            `json:"id,omitempty"`
	Serialized            string            `json:"serialized,omitempty"`
}

type Message struct {
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
	Message   string `json:"message"`
}

////////////////////////////////////////////////////////////////////////////////
// TRANSACTION ASSETS //////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

type TransactionAsset struct {
	Votes          []string
	Signature      *SecondSignatureRegistrationAsset
	Delegate       *DelegateAsset
	MultiSignature *MultiSignatureRegistrationAsset
}

type SecondSignatureRegistrationAsset struct {
	PublicKey string
}

type DelegateAsset struct {
	Username string
}

type MultiSignatureRegistrationAsset struct {
	Min       byte
	Keysgroup []string
	Lifetime  byte
}
