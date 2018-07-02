// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

package crypto

import (
	"encoding/hex"
	"fmt"
	"log"
	"strings"
)

func byte2hex(data byte) string {
	return fmt.Sprintf("%x", data)
}

func hex2byte(data []byte) string {
	return strings.ToLower(fmt.Sprintf("%X", data))
}

func hexDecode(data string) []byte {
	result, err := hex.DecodeString(data)

	if err != nil {
		log.Fatal(err.Error())
	}

	return result
}
