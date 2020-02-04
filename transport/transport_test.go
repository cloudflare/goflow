package transport

import (
	"testing"

	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/stretchr/testify/assert"
)

func TestHash(t *testing.T) {
	msg := &flowmessage.FlowMessage{
		SamplerAddress: []byte{10, 0, 0, 1},
	}
	key := HashProto([]string{"SamplerAddress", "InvalidField"}, msg)
	assert.Equal(t, "[10 0 0 1]-", key, "The two keys should be the same.")
}
