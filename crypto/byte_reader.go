// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"encoding/binary"
)

func ReadHex(data []byte) string {
	return string(HexDecode(Hex2Byte(data)))
}

func ReadInt8(data []byte) string {
	return Hex2Byte(data)
}

func ReadInt32(data []byte) uint32 {
	return binary.LittleEndian.Uint32(data)
}

func ReadInt64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}
