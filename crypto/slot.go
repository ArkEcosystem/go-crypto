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
