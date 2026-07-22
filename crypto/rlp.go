package crypto

import (
	"errors"
	"math/big"
)

var (
	ErrRlpUnsupportedType     = errors.New("rlp: unsupported type")
	ErrRlpUnexpectedEndOfData = errors.New("rlp: unexpected end of data")
	ErrRlpTooLarge            = errors.New("rlp: value too large")
	ErrRlpNegativeBigInt      = errors.New("rlp: cannot encode a negative big.Int")
)

const (
	rlpStringOffset   = 0x80
	rlpListOffset     = 0xc0
	rlpSingleByteMax  = 0x7f
	rlpShortStringMax = 0xb7
	rlpLongStringMax  = 0xbf
	rlpShortListMax   = 0xf7
)

// RlpItem is a value that can be RLP-encoded and decoded.
//
// https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
type RlpItem interface {
	EncodeRLP() ([]byte, error)
	DecodeRLP(data []byte) (int, error)
}

// RlpEncode encodes an RlpItem as RLP.
func RlpEncode(item RlpItem) ([]byte, error) {
	return item.EncodeRLP()
}

// RlpDecode decodes RLP-encoded data into item and returns the number of
// bytes read. The given data may be longer than the encoded item, in which
// case the remaining data is ignored.
func RlpDecode(data []byte, item RlpItem) (int, error) {
	return item.DecodeRLP(data)
}

// RlpBytes is an RLP byte string.
type RlpBytes []byte

func (s *RlpBytes) EncodeRLP() ([]byte, error) {
	if len(*s) == 1 && (*s)[0] <= rlpSingleByteMax {
		return []byte{(*s)[0]}, nil
	}

	prefix, err := rlpEncodePrefix(len(*s), rlpStringOffset)
	if err != nil {
		return nil, err
	}

	return append(prefix, *s...), nil
}

func (s *RlpBytes) DecodeRLP(data []byte) (int, error) {
	offset, dataLen, prefixLen, err := rlpDecodePrefix(data)
	if err != nil {
		return 0, err
	}
	if offset != rlpStringOffset {
		return 0, ErrRlpUnsupportedType
	}
	if uint64(len(data)) < uint64(prefixLen)+dataLen {
		return 0, ErrRlpUnexpectedEndOfData
	}

	*s = append([]byte{}, data[uint64(prefixLen):uint64(prefixLen)+dataLen]...)

	return prefixLen + int(dataLen), nil
}

// RlpBigInt is an RLP-encoded arbitrary-precision, non-negative integer.
// Zero always encodes as an empty RLP string.
type RlpBigInt struct{ X *big.Int }

func NewRlpBigInt(x *big.Int) *RlpBigInt {
	return &RlpBigInt{X: x}
}

func (b *RlpBigInt) EncodeRLP() ([]byte, error) {
	if b.X == nil || b.X.Sign() == 0 {
		empty := RlpBytes{}
		return empty.EncodeRLP()
	}
	if b.X.Sign() < 0 {
		return nil, ErrRlpNegativeBigInt
	}

	bytes := RlpBytes(b.X.Bytes())
	return bytes.EncodeRLP()
}

func (b *RlpBigInt) DecodeRLP(data []byte) (int, error) {
	s := RlpBytes{}

	n, err := s.DecodeRLP(data)
	if err != nil {
		return 0, err
	}

	b.X = new(big.Int).SetBytes(s)

	return n, nil
}

// RlpList is an ordered RLP list of items. When decoding, positions already
// populated with an item are decoded into that item's concrete type; any
// items beyond the pre-populated length are appended as raw RlpBytes.
type RlpList []RlpItem

func NewRlpList(items ...RlpItem) *RlpList {
	list := RlpList(items)
	return &list
}

func (l *RlpList) EncodeRLP() ([]byte, error) {
	payload := []byte{}

	for _, item := range *l {
		encoded, err := item.EncodeRLP()
		if err != nil {
			return nil, err
		}
		payload = append(payload, encoded...)
	}

	prefix, err := rlpEncodePrefix(len(payload), rlpListOffset)
	if err != nil {
		return nil, err
	}

	return append(prefix, payload...), nil
}

func (l *RlpList) DecodeRLP(data []byte) (int, error) {
	offset, dataLen, prefixLen, err := rlpDecodePrefix(data)
	if err != nil {
		return 0, err
	}
	if offset != rlpListOffset {
		return 0, ErrRlpUnsupportedType
	}
	if uint64(len(data)) < uint64(prefixLen)+dataLen {
		return 0, ErrRlpUnexpectedEndOfData
	}

	body := data[uint64(prefixLen) : uint64(prefixLen)+dataLen]

	for i := 0; len(body) > 0; i++ {
		var item RlpItem
		if i < len(*l) {
			item = (*l)[i]
		} else {
			item = &RlpBytes{}
			*l = append(*l, item)
		}

		consumed, err := item.DecodeRLP(body)
		if err != nil {
			return 0, err
		}

		body = body[consumed:]
	}

	return prefixLen + int(dataLen), nil
}

// rlpEncodePrefix encodes the RLP type-and-length prefix for offset
// (rlpStringOffset or rlpListOffset) and the given payload length.
func rlpEncodePrefix(length int, offset byte) ([]byte, error) {
	if length <= 55 {
		return []byte{offset + byte(length)}, nil
	}

	lengthBytes := rlpEncodeLength(uint64(length))
	if len(lengthBytes) > 8 {
		return nil, ErrRlpTooLarge
	}

	prefix := make([]byte, 0, 1+len(lengthBytes))
	prefix = append(prefix, offset+55+byte(len(lengthBytes)))
	prefix = append(prefix, lengthBytes...)

	return prefix, nil
}

// rlpEncodeLength returns the minimal big-endian encoding of length.
func rlpEncodeLength(length uint64) []byte {
	var buf [8]byte

	n := 0
	for length > 0 {
		buf[7-n] = byte(length)
		length >>= 8
		n++
	}

	return append([]byte{}, buf[8-n:]...)
}

// rlpDecodePrefix decodes the RLP type-and-length prefix at the start of
// data, returning which offset (rlpStringOffset or rlpListOffset) applies,
// the payload length, and the prefix length in bytes.
func rlpDecodePrefix(data []byte) (offset byte, dataLen uint64, prefixLen int, err error) {
	if len(data) == 0 {
		return 0, 0, 0, ErrRlpUnexpectedEndOfData
	}

	cur := data[0]

	switch {
	case cur <= rlpSingleByteMax:
		return rlpStringOffset, 1, 0, nil
	case cur <= rlpShortStringMax:
		return rlpStringOffset, uint64(cur - rlpStringOffset), 1, nil
	case cur <= rlpLongStringMax:
		lengthLen := int(cur - rlpShortStringMax)
		length, err := rlpReadUint(data[1:], lengthLen)
		if err != nil {
			return 0, 0, 0, err
		}
		return rlpStringOffset, length, 1 + lengthLen, nil
	case cur <= rlpShortListMax:
		return rlpListOffset, uint64(cur - rlpListOffset), 1, nil
	default:
		lengthLen := int(cur - rlpShortListMax)
		length, err := rlpReadUint(data[1:], lengthLen)
		if err != nil {
			return 0, 0, 0, err
		}
		return rlpListOffset, length, 1 + lengthLen, nil
	}
}

// rlpReadUint reads a big-endian unsigned integer of the given byte length.
func rlpReadUint(data []byte, length int) (uint64, error) {
	if length > 8 {
		return 0, ErrRlpTooLarge
	}
	if len(data) < length {
		return 0, ErrRlpUnexpectedEndOfData
	}

	var result uint64
	for i := 0; i < length; i++ {
		result = (result << 8) | uint64(data[i])
	}

	return result, nil
}
