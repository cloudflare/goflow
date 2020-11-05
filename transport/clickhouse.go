package transport

import (
	// "errors"
	"flag"
	"fmt"
	// "os"
	// "reflect"
	// "strings"

	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/cloudflare/goflow/v3/utils"
	// proto "github.com/golang/protobuf/proto"
)

var (
	ClickHouseAddr *string
	ClickHousePort *int
)

type ClickHouseState struct {
	FixedLengthProto bool
}


func RegisterFlags() {
	ClickHouseAddr   = flag.String("ch.addr", "127.0.0.1", "ClickHouse DB Host")
	ClickHousePort   = flag.Int("ch.port", 9000, "ClickHouse DB port")

	// future: add batch size to batch insert
}


func StartClickHouseConnection(log utils.Logger) (*ClickHouseState, error) {
	
	if ClickHouseAddr == nil {
        temp := "<nil>" // *string cannot be initialized
        ClickHouseAddr = &temp // in one statement
    }

	fmt.Printf("clickhouse server on %v:%v\n", *ClickHouseAddr, *ClickHousePort)

	state := ClickHouseState { FixedLengthProto: true }

	return &state, nil

	
}

func ipv4BytesToUint32(b []byte) (uint32) {
	return uint32(b[0]) << 24 + uint32(b[1]) << 16 + uint32(b[2]) << 8 + uint32(b[3])
}

func ClickHouseInsert(flowMessage *flowmessage.FlowMessage) {
	// extract fields out of the flow message
	

	// assume and encode as IPv4 (even if its v6)
	srcAddr := ipv4BytesToUint32(flowMessage.GetSrcAddr()[:4])
	dstAddr := ipv4BytesToUint32(flowMessage.GetDstAddr()[:4])
	

	 fmt.Printf("src (%v) %v:%v\ndst (%v) %v:%v\n------\n",
	 	srcAddr,
	 	flowMessage.GetSrcAddr(), 
		flowMessage.GetSrcPort(), 
		dstAddr,
		flowMessage.GetDstAddr(), 
		flowMessage.GetDstPort())


}

func (s ClickHouseState) Publish(msgs []*flowmessage.FlowMessage) {
	// ht: this is all you need to implement for the transport interface
	// needs to be async??
	for _, msg := range msgs {
		go ClickHouseInsert(msg)
	}
}
