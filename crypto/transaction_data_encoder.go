package crypto

import "math/big"

func EncodeVoteData(validatorAddress string) ([]byte, error) {
	voteArg, err := AbiAddress(validatorAddress)
	if err != nil {
		return nil, err
	}
	return AbiEncodeFunctionCall(AbiSignatureVote, voteArg), nil
}

func EncodeUnvoteData() []byte {
	return AbiEncodeFunctionCall(AbiSignatureUnvote)
}

func EncodeValidatorRegistrationData(validatorPassphrase string) ([]byte, error) {
	pop, err := FromMnemonic(validatorPassphrase)
	if err != nil {
		return nil, err
	}
	return AbiEncodeFunctionCall(AbiSignatureRegisterValidator, AbiBytes(pop.PK), AbiBytes(pop.POP)), nil
}

func EncodeValidatorUpdateData(validatorPassphrase string) ([]byte, error) {
	pop, err := FromMnemonic(validatorPassphrase)
	if err != nil {
		return nil, err
	}
	return AbiEncodeFunctionCall(AbiSignatureUpdateValidator, AbiBytes(pop.PK), AbiBytes(pop.POP)), nil
}

func EncodeValidatorResignationData() []byte {
	return AbiEncodeFunctionCall(AbiSignatureResignValidator)
}

func EncodeUsernameRegistrationData(username string) ([]byte, error) {
	if err := validateUsername(username); err != nil {
		return nil, err
	}
	return AbiEncodeFunctionCall(AbiSignatureRegisterUsername, AbiString(username)), nil
}

func EncodeUsernameResignationData() []byte {
	return AbiEncodeFunctionCall(AbiSignatureResignUsername)
}

func EncodeMultiPaymentData(addresses []string, amounts []*big.Int) ([]byte, error) {
	addressesArg, err := AbiAddressArray(addresses)
	if err != nil {
		return nil, err
	}
	amountsArg, err := AbiUint256Array(amounts)
	if err != nil {
		return nil, err
	}
	return AbiEncodeFunctionCall(AbiSignatureMultipayment, addressesArg, amountsArg), nil
}

func EncodeTokenTransferData(recipientAddress string, amount *big.Int) ([]byte, error) {
	recipientArg, err := AbiAddress(recipientAddress)
	if err != nil {
		return nil, err
	}
	amountArg, err := AbiUint256(amount)
	if err != nil {
		return nil, err
	}
	return AbiEncodeFunctionCall(AbiSignatureERC20Transfer, recipientArg, amountArg), nil
}

func EncodeApproveContractData(amount *big.Int) ([]byte, error) {
	spenderArg, err := AbiAddress(ContractBatchTransfer)
	if err != nil {
		return nil, err
	}
	amountArg, err := AbiUint256(amount)
	if err != nil {
		return nil, err
	}
	return AbiEncodeFunctionCall(AbiSignatureERC20Approve, spenderArg, amountArg), nil
}

func EncodeBatchTransferData(tokenAddress string, recipients []string, amounts []*big.Int) ([]byte, error) {
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
	return AbiEncodeFunctionCall(AbiSignatureERC20BatchTransferFrom, tokenArg, recipientsArg, amountsArg), nil
}
