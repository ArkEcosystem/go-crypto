// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

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
