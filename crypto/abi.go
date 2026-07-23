package crypto

import (
	"bytes"
	"errors"
	"math/big"

	"golang.org/x/crypto/sha3"
)

const abiWordLength = 32
const abiSelectorLength = 4
const abiAddressLength = 20

var (
	ErrAbiInvalidAddress      = errors.New("abi: invalid address")
	ErrAbiValueTooLarge       = errors.New("abi: value exceeds one word (32 bytes)")
	ErrAbiNegativeUint        = errors.New("abi: uint256 must be non-negative")
	ErrAbiUnexpectedEndOfData = errors.New("abi: unexpected end of data")
	ErrAbiSelectorMismatch    = errors.New("abi: function selector does not match")
	ErrAbiInvalidOffset       = errors.New("abi: dynamic value offset is invalid")
)

// AbiFunctionSelector returns the first 4 bytes of keccak256(signature), e.g.
// AbiFunctionSelector("vote(address)").
func AbiFunctionSelector(signature string) []byte {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(signature))
	return hash.Sum(nil)[:abiSelectorLength]
}

// AbiArg is a single already-ABI-encoded function argument, tagged with
// whether it belongs in the head (static) or tail (dynamic) section of a
// function call's calldata.
type AbiArg struct {
	Encoded []byte
	Dynamic bool
}

// AbiEncodeFunctionCall assembles a full function call: the 4-byte selector
// followed by the head/tail encoding of args, per the Solidity ABI spec —
// static args are encoded directly in the head, dynamic args contribute a
// 32-byte offset in the head and their data in the tail.
func AbiEncodeFunctionCall(signature string, args ...AbiArg) []byte {
	head := make([]byte, 0, len(args)*abiWordLength)
	tail := []byte{}
	headLen := len(args) * abiWordLength

	for _, arg := range args {
		if arg.Dynamic {
			offset := headLen + len(tail)
			head = append(head, abiEncodeSmallUintWord(offset)...)
			tail = append(tail, arg.Encoded...)
		} else {
			head = append(head, arg.Encoded...)
		}
	}

	result := make([]byte, 0, abiSelectorLength+len(head)+len(tail))
	result = append(result, AbiFunctionSelector(signature)...)
	result = append(result, head...)
	result = append(result, tail...)

	return result
}

// AbiAddress encodes a static "address" argument. address must be a
// "0x"-prefixed, 40-hex-char string.
func AbiAddress(address string) (AbiArg, error) {
	encoded, err := abiEncodeAddress(address)
	if err != nil {
		return AbiArg{}, err
	}
	return AbiArg{Encoded: encoded, Dynamic: false}, nil
}

// AbiUint256 encodes a static "uint256" argument.
func AbiUint256(x *big.Int) (AbiArg, error) {
	if x == nil || x.Sign() < 0 {
		return AbiArg{}, ErrAbiNegativeUint
	}

	encoded, err := abiEncodeUintWord(x)
	if err != nil {
		return AbiArg{}, err
	}

	return AbiArg{Encoded: encoded, Dynamic: false}, nil
}

// AbiBytes encodes a dynamic "bytes" argument.
func AbiBytes(data []byte) AbiArg {
	return AbiArg{Encoded: abiEncodeDynamicBytes(data), Dynamic: true}
}

// AbiString encodes a dynamic "string" argument.
func AbiString(s string) AbiArg {
	return AbiArg{Encoded: abiEncodeDynamicBytes([]byte(s)), Dynamic: true}
}

// AbiAddressArray encodes a dynamic "address[]" argument.
func AbiAddressArray(addresses []string) (AbiArg, error) {
	body := make([]byte, 0, len(addresses)*abiWordLength)

	for _, address := range addresses {
		word, err := abiEncodeAddress(address)
		if err != nil {
			return AbiArg{}, err
		}
		body = append(body, word...)
	}

	encoded := append(abiEncodeSmallUintWord(len(addresses)), body...)

	return AbiArg{Encoded: encoded, Dynamic: true}, nil
}

// AbiUint256Array encodes a dynamic "uint256[]" argument.
func AbiUint256Array(values []*big.Int) (AbiArg, error) {
	body := make([]byte, 0, len(values)*abiWordLength)

	for _, v := range values {
		if v == nil || v.Sign() < 0 {
			return AbiArg{}, ErrAbiNegativeUint
		}

		word, err := abiEncodeUintWord(v)
		if err != nil {
			return AbiArg{}, err
		}
		body = append(body, word...)
	}

	encoded := append(abiEncodeSmallUintWord(len(values)), body...)

	return AbiArg{Encoded: encoded, Dynamic: true}, nil
}

// abiPadWordLeft left-pads b into a 32-byte word. Callers must ensure
// len(b) <= abiWordLength.
func abiPadWordLeft(b []byte) []byte {
	word := make([]byte, abiWordLength)
	copy(word[abiWordLength-len(b):], b)
	return word
}

// abiEncodeUintWord encodes an arbitrary, possibly caller-supplied uint256,
// rejecting values that don't fit in one 32-byte word.
func abiEncodeUintWord(x *big.Int) ([]byte, error) {
	b := x.Bytes()
	if len(b) > abiWordLength {
		return nil, ErrAbiValueTooLarge
	}

	return abiPadWordLeft(b), nil
}

// abiEncodeSmallUintWord encodes a non-negative, internally-computed
// offset/length/count. Safe by construction, not just in practice: an int64's
// big-endian representation is at most 8 bytes, always well under the
// 32-byte word size, so there is no failure mode to check for.
func abiEncodeSmallUintWord(n int) []byte {
	return abiPadWordLeft(big.NewInt(int64(n)).Bytes())
}

func abiEncodeAddress(address string) ([]byte, error) {
	addressBytes, err := AddressToBytes(address)
	if err != nil {
		return nil, ErrAbiInvalidAddress
	}

	word := abiPadWordLeft(addressBytes)

	return word, nil
}

func abiEncodeDynamicBytes(data []byte) []byte {
	lengthWord := abiEncodeSmallUintWord(len(data))

	paddedLen := len(data)
	if rem := paddedLen % abiWordLength; rem != 0 {
		paddedLen += abiWordLength - rem
	}

	body := make([]byte, paddedLen)
	copy(body, data)

	return append(lengthWord, body...)
}

// AbiDecoder decodes the calldata of a single, known function call: the
// 4-byte selector followed by a flat sequence of 32-byte head words, one per
// top-level argument, where dynamic arguments' head word is an offset
// pointing into the tail section.
type AbiDecoder struct {
	head [][]byte
	tail []byte
}

// NewAbiDecoder validates that data starts with the given function selector
// and splits the remaining calldata into its head words and tail region,
// where argCount is the function's total number of top-level arguments.
func NewAbiDecoder(data []byte, signature string, argCount int) (*AbiDecoder, error) {
	if len(data) < abiSelectorLength {
		return nil, ErrAbiUnexpectedEndOfData
	}
	if !bytes.Equal(data[:abiSelectorLength], AbiFunctionSelector(signature)) {
		return nil, ErrAbiSelectorMismatch
	}

	body := data[abiSelectorLength:]
	if len(body) < argCount*abiWordLength {
		return nil, ErrAbiUnexpectedEndOfData
	}

	head := make([][]byte, argCount)
	for i := 0; i < argCount; i++ {
		head[i] = body[i*abiWordLength : (i+1)*abiWordLength]
	}

	return &AbiDecoder{head: head, tail: body}, nil
}

// Address decodes the argIndex-th argument as a static "address".
func (d *AbiDecoder) Address(argIndex int) (string, error) {
	word, err := d.headWord(argIndex)
	if err != nil {
		return "", err
	}

	return AddressFromBytes(word[abiWordLength-abiAddressLength:]), nil
}

// Uint256 decodes the argIndex-th argument as a static "uint256".
func (d *AbiDecoder) Uint256(argIndex int) (*big.Int, error) {
	word, err := d.headWord(argIndex)
	if err != nil {
		return nil, err
	}

	return new(big.Int).SetBytes(word), nil
}

// Bytes decodes the argIndex-th argument as a dynamic "bytes".
func (d *AbiDecoder) Bytes(argIndex int) ([]byte, error) {
	tailData, err := d.dynamicTail(argIndex)
	if err != nil {
		return nil, err
	}
	if len(tailData) < abiWordLength {
		return nil, ErrAbiUnexpectedEndOfData
	}

	lengthWord := tailData[:abiWordLength]
	tailData = tailData[abiWordLength:]

	length, err := abiWordToBoundedInt(lengthWord, len(tailData))
	if err != nil {
		return nil, err
	}

	return append([]byte{}, tailData[:length]...), nil
}

// String decodes the argIndex-th argument as a dynamic "string".
func (d *AbiDecoder) String(argIndex int) (string, error) {
	data, err := d.Bytes(argIndex)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// AddressArray decodes the argIndex-th argument as a dynamic "address[]".
func (d *AbiDecoder) AddressArray(argIndex int) ([]string, error) {
	tailData, err := d.dynamicTail(argIndex)
	if err != nil {
		return nil, err
	}

	count, elements, err := abiArrayElements(tailData)
	if err != nil {
		return nil, err
	}

	addresses := make([]string, count)
	for i := 0; i < count; i++ {
		word := elements[i*abiWordLength : (i+1)*abiWordLength]
		addresses[i] = AddressFromBytes(word[abiWordLength-abiAddressLength:])
	}

	return addresses, nil
}

// Uint256Array decodes the argIndex-th argument as a dynamic "uint256[]".
func (d *AbiDecoder) Uint256Array(argIndex int) ([]*big.Int, error) {
	tailData, err := d.dynamicTail(argIndex)
	if err != nil {
		return nil, err
	}

	count, elements, err := abiArrayElements(tailData)
	if err != nil {
		return nil, err
	}

	values := make([]*big.Int, count)
	for i := 0; i < count; i++ {
		values[i] = new(big.Int).SetBytes(elements[i*abiWordLength : (i+1)*abiWordLength])
	}

	return values, nil
}

func abiArrayElements(tailData []byte) (int, []byte, error) {
	if len(tailData) < abiWordLength {
		return 0, nil, ErrAbiUnexpectedEndOfData
	}

	elements := tailData[abiWordLength:]

	count, err := abiWordToBoundedInt(tailData[:abiWordLength], len(elements)/abiWordLength)
	if err != nil {
		return 0, nil, err
	}

	return count, elements, nil
}

func (d *AbiDecoder) headWord(argIndex int) ([]byte, error) {
	if argIndex < 0 || argIndex >= len(d.head) {
		return nil, ErrAbiUnexpectedEndOfData
	}
	return d.head[argIndex], nil
}

// dynamicTail follows the offset stored in the argIndex-th head word and
// returns the tail data starting at that offset.
func (d *AbiDecoder) dynamicTail(argIndex int) ([]byte, error) {
	word, err := d.headWord(argIndex)
	if err != nil {
		return nil, err
	}

	offset, err := abiWordToBoundedInt(word, len(d.tail))
	if err != nil {
		return nil, ErrAbiInvalidOffset
	}

	return d.tail[offset:], nil
}

// abiWordToBoundedInt reads a 32-byte ABI word as a length/offset/count value,
// rejecting it unless it is non-negative and no greater than maxLen. This
// guards against a malformed or adversarial word causing big.Int.Int64()
// overflow, or a value that would later be used as an allocation size or
// slice bound before the available data has been confirmed to support it.
func abiWordToBoundedInt(word []byte, maxLen int) (int, error) {
	v := new(big.Int).SetBytes(word)
	if !v.IsInt64() {
		return 0, ErrAbiInvalidOffset
	}

	n := v.Int64()
	if n < 0 || n > int64(maxLen) {
		return 0, ErrAbiInvalidOffset
	}

	return int(n), nil
}
