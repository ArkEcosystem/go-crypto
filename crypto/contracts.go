package crypto

const (
	ContractConsensus     = "0x535B3D7A252fa034Ed71F0C53ec0C6F784cB64E1"
	ContractMultipayment  = "0x00EFd0D4639191C49908A7BddbB9A11A994A8527"
	ContractUsernames     = "0x2c1DE3b4Dbb4aDebEbB5dcECAe825bE2a9fc6eb6"
	ContractBatchTransfer = "0x5a223F4434D5Bd8478100EEb3b0166a57A26350d"
)

const (
	AbiSignatureVote                   = "vote(address)"
	AbiSignatureUnvote                 = "unvote()"
	AbiSignatureRegisterValidator      = "registerValidator(bytes,bytes)"
	AbiSignatureResignValidator        = "resignValidator()"
	AbiSignatureUpdateValidator        = "updateValidator(bytes,bytes)"
	AbiSignatureRegisterUsername       = "registerUsername(string)"
	AbiSignatureResignUsername         = "resignUsername()"
	AbiSignatureMultipayment           = "pay(address[],uint256[])"
	AbiSignatureERC20Transfer          = "transfer(address,uint256)"
	AbiSignatureERC20Approve           = "approve(address,uint256)"
	AbiSignatureERC20BatchTransferFrom = "batchTransferFrom(address,address[],uint256[])"
)
