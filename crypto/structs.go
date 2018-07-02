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
	Transfer                    int
	SecondSignatureRegistration int
	DelegateRegistration        int
	Vote                        int
	MultiSignatureRegistration  int
	Ipfs                        int
	TimelockTransfer            int
	MultiPayment                int
	DelegateResignation         int
}

type Transaction struct {
	Header          string            `json:"header,omitempty"`
	Version         string            `json:"version,omitempty"`
	Network         string            `json:"network,omitempty"`
	Type            string            `json:"type,omitempty"`
	Timestamp       uint32            `json:"timestamp,omitempty"`
	SenderPublicKey string            `json:"senderPublicKey,omitempty"`
	Fee             string            `json:"fee,omitempty"`
	VendorFieldHex  string            `json:"vendorFieldHex,omitempty"`
	Amount          int64             `json:"amount,omitempty"`
	Expiration      int32             `json:"expiration,omitempty"`
	RecipientId     string            `json:"recipientId,omitempty"`
	Signature       string            `json:"signature,omitempty"`
	VendorField     string            `json:"vendorField,omitempty"`
	Asset           map[string]string `json:"asset,omitempty"`
	Id              string            `json:"id,omitempty"`
	Serialized      string            `json:"serialized,omitempty"`
}

type Message struct {
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
	Message   string `json:"message"`
}
