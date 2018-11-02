// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import "time"

func GetTime() int32 {
	now := time.Now()
	diff := now.Sub(GetNetwork().Epoch)

	return int32(diff.Seconds())
}

func GetEpoch() uint32 {
	return uint32(GetNetwork().Epoch.Second())
}
