package crypto

import (
	"bytes"
	"encoding/hex"
	"math/big"
)

// Deliberately unlike php-crypto (which silently swallows any decode error
// and falls through to the next candidate, even after a selector match):
// once transaction.Data's leading 4 bytes match a known function's selector,
// any further decode failure is treated as a genuinely malformed transaction
// of that kind and returned as an error, rather than silently ignored.
func DecodeTransactionArgs(transaction *Transaction) error {
	type candidate struct {
		signature string
		argCount  int
		apply     func(*Transaction, *AbiDecoder) error
	}

	candidates := []candidate{
		{AbiSignatureVote, 1, applyVote},
		{AbiSignatureUnvote, 0, applyUnvote},
		{AbiSignatureRegisterValidator, 2, applyValidatorRegistration},
		{AbiSignatureResignValidator, 0, applyValidatorResignation},
		{AbiSignatureUpdateValidator, 2, applyValidatorUpdate},
		{AbiSignatureRegisterUsername, 1, applyUsernameRegistration},
		{AbiSignatureResignUsername, 0, applyUsernameResignation},
		{AbiSignatureMultipayment, 2, applyMultiPayment},
	}

	for _, c := range candidates {
		if !dataHasSelector(transaction.Data, c.signature) {
			continue
		}

		decoder, err := NewAbiDecoder(transaction.Data, c.signature, c.argCount)
		if err != nil {
			return err
		}

		return c.apply(transaction, decoder)
	}

	return nil
}

func dataHasSelector(data []byte, signature string) bool {
	if len(data) < abiSelectorLength {
		return false
	}
	return bytes.Equal(data[:abiSelectorLength], AbiFunctionSelector(signature))
}

func applyVote(transaction *Transaction, decoder *AbiDecoder) error {
	vote, err := decoder.Address(0)
	if err != nil {
		return err
	}
	transaction.Vote = vote
	return nil
}

func applyUnvote(transaction *Transaction, _ *AbiDecoder) error {
	return nil
}

func applyValidatorRegistration(transaction *Transaction, decoder *AbiDecoder) error {
	pubKey, err := decoder.Bytes(0)
	if err != nil {
		return err
	}
	proof, err := decoder.Bytes(1)
	if err != nil {
		return err
	}
	transaction.ValidatorPublicKey = hex.EncodeToString(pubKey)
	transaction.ValidatorProof = hex.EncodeToString(proof)
	return nil
}

func applyValidatorResignation(transaction *Transaction, _ *AbiDecoder) error {
	return nil
}

func applyValidatorUpdate(transaction *Transaction, decoder *AbiDecoder) error {
	pubKey, err := decoder.Bytes(0)
	if err != nil {
		return err
	}
	proof, err := decoder.Bytes(1)
	if err != nil {
		return err
	}
	transaction.ValidatorPublicKey = hex.EncodeToString(pubKey)
	transaction.ValidatorProof = hex.EncodeToString(proof)
	return nil
}

func applyUsernameRegistration(transaction *Transaction, decoder *AbiDecoder) error {
	username, err := decoder.String(0)
	if err != nil {
		return err
	}
	transaction.Username = username
	return nil
}

func applyUsernameResignation(transaction *Transaction, _ *AbiDecoder) error {
	return nil
}

func applyMultiPayment(transaction *Transaction, decoder *AbiDecoder) error {
	addresses, err := decoder.AddressArray(0)
	if err != nil {
		return err
	}
	amounts, err := decoder.Uint256Array(1)
	if err != nil {
		return err
	}
	transaction.PaymentAddresses = addresses
	transaction.PaymentAmounts = amounts
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// TRANSACTION TYPE IDENTIFIER /////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
// The functions below mirror typescript-crypto's TransactionTypeIdentifier:
// standalone, public, stateless predicates over raw calldata, computed fresh
// on every call — no stored/cached classification anywhere. This is the
// pattern actually exercised by real consumers of the sibling SDKs (e.g.
// arkvault calls TransactionTypeIdentifier.isTokenTransfer(...) directly on
// data it already has), as opposed to the full class-based Deserializer
// dispatch, which nothing outside the SDKs themselves calls.
//
// IsTransfer matches typescript-crypto's own rule (empty calldata), which is
// a different check than the value-based rule Deserializer.deserialize uses
// internally (value != 0) — that inconsistency exists in the reference
// implementation itself, not introduced here.

func IsTransfer(data []byte) bool {
	return len(data) == 0
}

func IsVote(data []byte) bool {
	return dataHasSelector(data, AbiSignatureVote)
}

func IsUnvote(data []byte) bool {
	return dataHasSelector(data, AbiSignatureUnvote)
}

func IsMultiPayment(data []byte) bool {
	return dataHasSelector(data, AbiSignatureMultipayment)
}

func IsUsernameRegistration(data []byte) bool {
	return dataHasSelector(data, AbiSignatureRegisterUsername)
}

func IsUsernameResignation(data []byte) bool {
	return dataHasSelector(data, AbiSignatureResignUsername)
}

func IsValidatorRegistration(data []byte) bool {
	return dataHasSelector(data, AbiSignatureRegisterValidator)
}

func IsValidatorResignation(data []byte) bool {
	return dataHasSelector(data, AbiSignatureResignValidator)
}

func IsUpdateValidator(data []byte) bool {
	return dataHasSelector(data, AbiSignatureUpdateValidator)
}

func IsTokenTransfer(data []byte) bool {
	return dataHasSelector(data, AbiSignatureERC20Transfer)
}

func IsBatchTransfer(data []byte) bool {
	_, err := NewAbiDecoder(data, AbiSignatureERC20BatchTransferFrom, 3)
	return err == nil
}

// IsApprove and IsRevoke both match approve(address,uint256); only the
// decoded amount (positive vs zero) tells them apart.
func IsApprove(data []byte) bool {
	amount, ok := decodedApproveAmount(data)
	return ok && amount.Sign() > 0
}

func IsRevoke(data []byte) bool {
	amount, ok := decodedApproveAmount(data)
	return ok && amount.Sign() == 0
}

func decodedApproveAmount(data []byte) (amount *big.Int, ok bool) {
	decoder, err := NewAbiDecoder(data, AbiSignatureERC20Approve, 2)
	if err != nil {
		return nil, false
	}
	amount, err = decoder.Uint256(1)
	if err != nil {
		return nil, false
	}
	return amount, true
}
