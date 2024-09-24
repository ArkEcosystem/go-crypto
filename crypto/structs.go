// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/json"
	"strconv"
	"time"

	"github.com/btcsuite/btcd/btcec"
	blst "github.com/supranational/blst/bindings/go"
)

type FlexToshi uint64

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
	Transfer                    uint16
	ValidatorRegistration       uint16
	Vote                        uint16
	MultiSignatureRegistration  uint16
	MultiPayment                uint16
	ValidatorResignation        uint16
	UsernameRegistration        uint16
	UsernameResignation         uint16
}

type TransactionTypeGroups struct {
	Test uint32
	Core uint32
}

type TransactionFees struct {
	Transfer                    FlexToshi
	ValidatorRegistration       FlexToshi
	Vote                        FlexToshi
	MultiSignatureRegistration  FlexToshi
	MultiPayment                FlexToshi
	ValidatorResignation        FlexToshi
	UsernameRegistration        FlexToshi
	UsernameResignation         FlexToshi
}

func (fi *FlexToshi) UnmarshalJSON(b []byte) error {
	if b[0] != '"' {
		return json.Unmarshal(b, (*uint64)(fi))
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}
	*fi = FlexToshi(i)
	return nil
}

type Transaction struct {
	Amount                FlexToshi         `json:"amount,omitempty"`
	Asset                 *TransactionAsset `json:"asset,omitempty"`
	Expiration            uint32            `json:"expiration,omitempty"`
	Fee                   FlexToshi         `json:"fee,omitempty"`
	Id                    string            `json:"id,omitempty"`
	Network               byte              `json:"network,omitempty"`
	Nonce                 uint64            `json:"nonce,omitempty,string"`
	RecipientId           string            `json:"recipientId,omitempty"`
	SecondSenderPublicKey string            `json:"secondSenderPublicKey,omitempty"`
	SecondSignature       string            `json:"secondSignature,omitempty"`
	SenderPublicKey       string            `json:"senderPublicKey,omitempty"`
	Serialized            []byte            `json:"serialized,omitempty"`
	Signature             string            `json:"signature,omitempty"`
	Signatures            []string          `json:"signatures,omitempty"`
	Timestamp             int32             `json:"timestamp,omitempty"`
	Type                  uint16            `json:"type"`
	TypeGroup             uint32            `json:"typeGroup"`
	VendorField           string            `json:"vendorField,omitempty"`
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
	Unvotes        []string                          `json:"unvotes,omitempty"`
	Validator      *ValidatorAsset                   `json:"validator,omitempty"`
	Username       *UsernameAsset                   `json:"validator,omitempty"`
	MultiSignature *MultiSignatureRegistrationAsset  `json:"multiSignature,omitempty"`
	Payments       []*MultiPaymentAsset              `json:"payments,omitempty"`
}

type ValidatorAsset struct {
	ValidatorPublicKey string `json:"validatorPublicKey,omitempty"`
}

type UsernameAsset struct {
	Username string `json:"username,omitempty"`
}

type MultiSignatureRegistrationAsset struct {
	Min        byte     `json:"min,omitempty"`
	PublicKeys []string `json:"publicKeys,omitempty"`
}

type MultiPaymentAsset struct {
	Amount      FlexToshi `json:"amount,omitempty"`
	RecipientId string    `json:"recipientId,omitempty"`
}

type BLSPrivateKey struct {
	PrivateKey *blst.SecretKey
}

type BLSPublicKey struct {
	PublicKey *blst.P1Affine
}

type BLSPrivateKey struct {
	PrivateKey *blst.SecretKey
}

type BLSPublicKey struct {
	PublicKey *blst.P1Affine
}
