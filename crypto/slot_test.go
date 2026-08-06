package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEpoch(t *testing.T) {
	assert.Equal(t, uint32(GetNetwork().Epoch.Unix()), GetEpoch())
	assert.EqualValues(t, 1490101200, GetEpoch()) // 2017-03-21T13:00:00Z
}

func TestGetTime(t *testing.T) {
	assert.Greater(t, GetTime(), int32(0))
}
