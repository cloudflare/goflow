package producer

import (
	"github.com/cloudflare/goflow/decoders/netflow"
	"github.com/cloudflare/goflow/decoders/sflow"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProcessMessageNetFlow(t *testing.T) {
	records := []netflow.DataRecord{
		netflow.DataRecord{
			Values: []netflow.DataField{
				netflow.DataField{
					Type:  netflow.NFV9_FIELD_IPV4_SRC_ADDR,
					Value: []byte{10, 0, 0, 1},
				},
			},
		},
	}
	dfs := []interface{}{
		netflow.DataFlowSet{
			Records: records,
		},
	}

	pktnf9 := netflow.NFv9Packet{
		FlowSets: dfs,
	}
	testsr := &SingleSamplingRateSystem{1}
	_, err := ProcessMessageNetFlow(pktnf9, testsr)
	assert.Nil(t, err)

	pktipfix := netflow.IPFIXPacket{
		FlowSets: dfs,
	}
	_, err = ProcessMessageNetFlow(pktipfix, testsr)
	assert.Nil(t, err)
}

func TestProcessMessageSFlow(t *testing.T) {
	sh := sflow.SampledHeader{
		FrameLength: 10,
		Protocol:    1,
		HeaderData: []byte{
			0xff, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xff, 0xab, 0xcd, 0xef, 0xab, 0xbc, 0x86, 0xdd, 0x60, 0x2e,
			0xc4, 0xec, 0x01, 0xcc, 0x06, 0x40, 0xfd, 0x01, 0x00, 0x00, 0xff, 0x01, 0x82, 0x10, 0xcd, 0xff,
			0xff, 0x1c, 0x00, 0x00, 0x01, 0x50, 0xfd, 0x01, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x02, 0xff,
			0xff, 0x93, 0x00, 0x00, 0x02, 0x46, 0xcf, 0xca, 0x00, 0x50, 0x05, 0x15, 0x21, 0x6f, 0xa4, 0x9c,
			0xf4, 0x59, 0x80, 0x18, 0x08, 0x09, 0x8c, 0x86, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x2a, 0x85,
			0xee, 0x9e, 0x64, 0x5c, 0x27, 0x28,
		},
	}
	pkt := sflow.Packet{
		Version: 5,
		Samples: []interface{}{
			sflow.FlowSample{
				SamplingRate: 1,
				Records: []sflow.FlowRecord{
					sflow.FlowRecord{
						Data: sh,
					},
				},
			},
			sflow.ExpandedFlowSample{
				SamplingRate: 1,
				Records: []sflow.FlowRecord{
					sflow.FlowRecord{
						Data: sh,
					},
				},
			},
		},
	}
	_, err := ProcessMessageSFlow(pkt)
	assert.Nil(t, err)
}
