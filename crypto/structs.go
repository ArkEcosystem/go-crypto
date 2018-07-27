// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"time"

	"github.com/btcsuite/btcd/btcec"
)

type Network struct {
	Epoch   time.Time
	Version byte
	Wif     byte
}

type PrivateKey struct {
	*btcec.PrivateKey
	PublicKey *PublicKey
}

type PublicKey struct {
	*btcec.PublicKey
	isCompressed bool
	Network      *Network
}

type TransactionTypes struct {
	Transfer                    byte
	SecondSignatureRegistration byte
	DelegateRegistration        byte
	Vote                        byte
	MultiSignatureRegistration  byte
	Ipfs                        byte
	TimelockTransfer            byte
	MultiPayment                byte
	DelegateResignation         byte
}

type TransactionFees struct {
	Transfer                    uint64
	SecondSignatureRegistration uint64
	DelegateRegistration        uint64
	Vote                        uint64
	MultiSignatureRegistration  uint64
	Ipfs                        uint64
	TimelockTransfer            uint64
	MultiPayment                uint64
	DelegateResignation         uint64
}

type Transaction struct {
	Amount                uint64            `json:"amount,omitempty"`
	Asset                 *TransactionAsset `json:"asset,omitempty"`
	Expiration            uint32            `json:"expiration,omitempty"`
	Fee                   uint64            `json:"fee,omitempty"`
	Id                    string            `json:"id,omitempty"`
	Network               byte              `json:"network,omitempty"`
	RecipientId           string            `json:"recipientId,omitempty"`
	SecondSenderPublicKey string            `json:"secondSenderPublicKey,omitempty"`
	SecondSignature       string            `json:"secondSignature,omitempty"`
	SenderPublicKey       string            `json:"senderPublicKey,omitempty"`
	Serialized            string            `json:"serialized,omitempty"`
	Signature             string            `json:"signature,omitempty"`
	Signatures            []string          `json:"signatures,omitempty"`
	SignSignature         string            `json:"signSignature,omitempty"`
	Timelock              uint32            `json:"timelock,omitempty"`
	TimelockType          string            `json:"timelockType,omitempty"`
	Timestamp             uint32            `json:"timestamp,omitempty"`
	Type                  byte              `json:"type"`
	VendorField           string            `json:"vendorField,omitempty"`
	VendorFieldHex        []byte            `json:"vendorFieldHex,omitempty"`
	Version               byte              `json:"version,omitempty"`
}

type Message struct {
	Message   string `json:"message"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
}

////////////////////////////////////////////////////////////////////////////////
// TRANSACTION ASSETS //////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

type TransactionAsset struct {
	Votes          []string                          `json:"votes,omitempty"`
	Dag            string                            `json:"dag,omitempty"`
	Signature      *SecondSignatureRegistrationAsset `json:"signature,omitempty"`
	Delegate       *DelegateAsset                    `json:"delegate,omitempty"`
	MultiSignature *MultiSignatureRegistrationAsset  `json:"multisignature,omitempty"`
	Ipfs           *IpfsAsset                        `json:"ipfs,omitempty"`
	Payments       []*MultiPaymentAsset              `json:"payments,omitempty"`
}

type SecondSignatureRegistrationAsset struct {
	PublicKey string `json:"publicKey,omitempty"`
}

type DelegateAsset struct {
	Username string `json:"username,omitempty"`
}

type MultiSignatureRegistrationAsset struct {
	Min       byte     `json:"min,omitempty"`
	Keysgroup []string `json:"keysgroup,omitempty"`
	Lifetime  byte     `json:"lifetime,omitempty"`
}

type IpfsAsset struct {
	Dag string `json:"dag,omitempty"`
}

type MultiPaymentAsset struct {
	Amount      uint64 `json:"amount,omitempty"`
	RecipientId string `json:"recipientId,omitempty"`
}
