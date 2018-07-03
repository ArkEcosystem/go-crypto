// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import "time"

func GetTime() uint32 {
	now := time.Now()
	diff := now.Sub(GetNetwork().Epoch)
	return uint32(diff.Seconds())
}

func GetDurationTime(timestamp uint32) int {
	var durationSeconds time.Duration = time.Duration(timestamp) * time.Second
	timeCalculcated := GetNetwork().Epoch.Add(durationSeconds)

	now := time.Now()
	diff := now.Sub(timeCalculcated)

	return int(diff.Hours())
}

func GetTransactionTime(timestamp uint32) time.Time {
	var durationSeconds time.Duration = time.Duration(timestamp) * time.Second
	timeCalculcated := GetNetwork().Epoch.Add(durationSeconds)

	return timeCalculcated
}
