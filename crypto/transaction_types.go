package crypto

import (
	"bytes"
	"encoding/hex"
	"math/big"
)

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
