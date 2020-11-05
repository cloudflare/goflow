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
	fmt.Printf("clickhouse server on: %v:%v \n", ClickHouseAddr, ClickHousePort)

	state := ClickHouseState { FixedLengthProto: true }

	return &state, nil

	
}

func ClickHouseInsert(flowMessage *flowmessage.FlowMessage) {
	// turn the fields into stuff
	fmt.Printf("Inserting message %v", flowMessage)

}

func (s ClickHouseState) Publish(msgs []*flowmessage.FlowMessage) {
	// ht: this is all you need to implement for the transport interface
	// needs to be async??
	for _, msg := range msgs {
		go ClickHouseInsert(msg)
	}
}
