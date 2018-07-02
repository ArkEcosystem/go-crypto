// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"encoding/hex"
	"log"
)

func hexDecode(data string) []byte {
	result, err := hex.DecodeString(data)

	if err != nil {
		log.Fatal(err.Error())
	}

	return result
}