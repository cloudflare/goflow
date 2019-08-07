package transport

import (
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHash(t *testing.T) {
	msg := &flowmessage.FlowMessage{
		SamplerAddress: []byte{10, 0, 0, 1},
	}
	key := HashProto([]string{"SamplerAddress", "InvalidField"}, msg)
	assert.Equal(t, "[10 0 0 1]-", key, "The two keys should be the same.")
}
