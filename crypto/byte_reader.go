// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/binary"
)

func ReadHex(data []byte) string {
	return string(HexDecode(Hex2Byte(data)))
}

func ReadInt8(data []byte) byte {
	return data[0]
}

func ReadInt32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data)
}

func ReadInt64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}
