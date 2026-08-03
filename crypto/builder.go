package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
)

var (
	DefaultGasPrice = big.NewInt(5)
	DefaultGasLimit = big.NewInt(1_000_000)
)

// Concrete transaction-type builders (BuildTransfer, BuildVote, etc.) are
// layered on top of this.
func NewTransaction() *Transaction {
	return &Transaction{
		Nonce:    big.NewInt(1),
		GasPrice: DefaultGasPrice,
		GasLimit: DefaultGasLimit,
		Value:    big.NewInt(0),
	}
}

func BuildTransfer(to string, value *big.Int) (*Transaction, error) {
	if _, err := AddressToBytes(to); err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = to
	transaction.Value = bigIntOrZero(value)

	return transaction, nil
}

func BuildVote(validatorAddress string) (*Transaction, error) {
	voteArg, err := AbiAddress(validatorAddress)
	if err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = ContractConsensus
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureVote, voteArg)
	transaction.Vote = validatorAddress

	return transaction, nil
}

func BuildUnvote() *Transaction {
	transaction := NewTransaction()
	transaction.To = ContractConsensus
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureUnvote)

	return transaction
}

func BuildValidatorRegistration(validatorPassphrase string, stake *big.Int) (*Transaction, error) {
	pop, err := FromMnemonic(validatorPassphrase)
	if err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = ContractConsensus
	transaction.Value = bigIntOrZero(stake)
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureRegisterValidator, AbiBytes(pop.PK), AbiBytes(pop.POP))
	transaction.ValidatorPublicKey = hex.EncodeToString(pop.PK)
	transaction.ValidatorProof = hex.EncodeToString(pop.POP)

	return transaction, nil
}

func BuildValidatorUpdate(validatorPassphrase string) (*Transaction, error) {
	pop, err := FromMnemonic(validatorPassphrase)
	if err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = ContractConsensus
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureUpdateValidator, AbiBytes(pop.PK), AbiBytes(pop.POP))
	transaction.ValidatorPublicKey = hex.EncodeToString(pop.PK)
	transaction.ValidatorProof = hex.EncodeToString(pop.POP)

	return transaction, nil
}

func BuildValidatorResignation() *Transaction {
	transaction := NewTransaction()
	transaction.To = ContractConsensus
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureResignValidator)

	return transaction
}

var (
	ErrInvalidUsername = errors.New("crypto: invalid username")

	usernameCharsetRegexp          = regexp.MustCompile(`[^a-z0-9_]`)
	usernameEdgeUnderscoreRegexp   = regexp.MustCompile(`^_|_$`)
	usernameDoubleUnderscoreRegexp = regexp.MustCompile(`__`)
)

func validateUsername(username string) error {
	if len(username) < 1 || len(username) > 20 {
		return fmt.Errorf("%w: must be between 1 and 20 characters long, got %d", ErrInvalidUsername, len(username))
	}
	if usernameCharsetRegexp.MatchString(username) {
		return fmt.Errorf("%w: can only contain lowercase letters, numbers and underscores", ErrInvalidUsername)
	}
	if usernameEdgeUnderscoreRegexp.MatchString(username) {
		return fmt.Errorf("%w: cannot start or end with an underscore", ErrInvalidUsername)
	}
	if usernameDoubleUnderscoreRegexp.MatchString(username) {
		return fmt.Errorf("%w: cannot contain consecutive underscores", ErrInvalidUsername)
	}
	return nil
}

func BuildUsernameRegistration(username string) (*Transaction, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = ContractUsernames
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureRegisterUsername, AbiString(username))
	transaction.Username = username

	return transaction, nil
}

func BuildUsernameResignation() *Transaction {
	transaction := NewTransaction()
	transaction.To = ContractUsernames
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureResignUsername)

	return transaction
}

func BuildMultiPayment(addresses []string, amounts []*big.Int) (*Transaction, error) {
	if len(addresses) != len(amounts) {
		return nil, fmt.Errorf("crypto: multi-payment addresses and amounts must be the same length, got %d and %d", len(addresses), len(amounts))
	}
	if len(addresses) == 0 {
		return nil, errors.New("crypto: multi-payment requires at least one recipient")
	}

	addressesArg, err := AbiAddressArray(addresses)
	if err != nil {
		return nil, err
	}
	amountsArg, err := AbiUint256Array(amounts)
	if err != nil {
		return nil, err
	}

	total := big.NewInt(0)
	for _, amount := range amounts {
		total.Add(total, amount)
	}

	transaction := NewTransaction()
	transaction.To = ContractMultipayment
	transaction.Value = total
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureMultipayment, addressesArg, amountsArg)
	transaction.PaymentAddresses = addresses
	transaction.PaymentAmounts = amounts

	return transaction, nil
}

func BuildEvmCall(to string, data []byte) (*Transaction, error) {
	if _, err := AddressToBytes(to); err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = to
	transaction.Data = data

	return transaction, nil
}

func BuildBatchTransfer(tokenAddress string, recipients []string, amounts []*big.Int) (*Transaction, error) {
	if len(recipients) != len(amounts) {
		return nil, fmt.Errorf("crypto: batch transfer recipients and amounts must be the same length, got %d and %d", len(recipients), len(amounts))
	}
	if len(recipients) == 0 {
		return nil, errors.New("crypto: batch transfer requires at least one recipient")
	}

	tokenArg, err := AbiAddress(tokenAddress)
	if err != nil {
		return nil, err
	}
	recipientsArg, err := AbiAddressArray(recipients)
	if err != nil {
		return nil, err
	}
	amountsArg, err := AbiUint256Array(amounts)
	if err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = ContractBatchTransfer
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureERC20BatchTransferFrom, tokenArg, recipientsArg, amountsArg)

	return transaction, nil
}

func BuildTokenApprove(tokenAddress string, spender string, amount *big.Int) (*Transaction, error) {
	if _, err := AddressToBytes(tokenAddress); err != nil {
		return nil, err
	}

	spenderArg, err := AbiAddress(spender)
	if err != nil {
		return nil, err
	}
	amountArg, err := AbiUint256(amount)
	if err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = tokenAddress
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureERC20Approve, spenderArg, amountArg)

	return transaction, nil
}

func BuildTokenTransfer(tokenAddress string, recipient string, amount *big.Int) (*Transaction, error) {
	if _, err := AddressToBytes(tokenAddress); err != nil {
		return nil, err
	}

	recipientArg, err := AbiAddress(recipient)
	if err != nil {
		return nil, err
	}
	amountArg, err := AbiUint256(amount)
	if err != nil {
		return nil, err
	}

	transaction := NewTransaction()
	transaction.To = tokenAddress
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureERC20Transfer, recipientArg, amountArg)

	return transaction, nil
}
