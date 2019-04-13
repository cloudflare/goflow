package netflowlegacy

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type PacketNetFlowV5 struct {
	Version          uint16
	Count            uint16
	SysUptime        uint32
	UnixSecs         uint32
	UnixNSecs        uint32
	FlowSequence     uint32
	EngineType       uint8
	EngineId         uint8
	SamplingInterval uint16
	Records          []RecordsNetFlowV5
}

type RecordsNetFlowV5 struct {
	SrcAddr  uint32
	DstAddr  uint32
	NextHop  uint32
	Input    uint16
	Output   uint16
	DPkts    uint32
	DOctets  uint32
	First    uint32
	Last     uint32
	SrcPort  uint16
	DstPort  uint16
	Pad1     byte
	TCPFlags uint8
	Proto    uint8
	Tos      uint8
	SrcAS    uint16
	DstAS    uint16
	SrcMask  uint8
	DstMask  uint8
	Pad2     uint16
}

func (p PacketNetFlowV5) String() string {
	str := "NetFlow v5 Packet\n"
	str += "-----------------\n"
	str += fmt.Sprintf("  Version: %v\n", p.Version)
	str += fmt.Sprintf("  Count:  %v\n", p.Count)

	unixSeconds := time.Unix(int64(p.UnixSecs), int64(p.UnixNSecs))
	str += fmt.Sprintf("  SystemUptime: %v\n", time.Duration(p.SysUptime)*time.Millisecond)
	str += fmt.Sprintf("  UnixSeconds: %v\n", unixSeconds.String())
	str += fmt.Sprintf("  FlowSequence: %v\n", p.FlowSequence)
	str += fmt.Sprintf("  EngineType: %v\n", p.EngineType)
	str += fmt.Sprintf("  EngineId: %v\n", p.EngineId)
	str += fmt.Sprintf("  SamplingInterval: %v\n", p.SamplingInterval)
	str += fmt.Sprintf("  Records (%v):\n", len(p.Records))

	for i, record := range p.Records {
		str += fmt.Sprintf("    Record %v:\n", i)
		str += record.String()
	}
	return str
}

func (r RecordsNetFlowV5) String() string {
	srcaddr := make(net.IP, 4)
	binary.BigEndian.PutUint32(srcaddr, r.SrcAddr)
	dstaddr := make(net.IP, 4)
	binary.BigEndian.PutUint32(dstaddr, r.DstAddr)
	nexthop := make(net.IP, 4)
	binary.BigEndian.PutUint32(nexthop, r.NextHop)

	str := fmt.Sprintf("      SrcAddr: %v\n", srcaddr.String())
	str += fmt.Sprintf("      DstAddr: %v\n", dstaddr.String())
	str += fmt.Sprintf("      NextHop: %v\n", nexthop.String())
	str += fmt.Sprintf("      Input: %v\n", r.Input)
	str += fmt.Sprintf("      Output: %v\n", r.Output)
	str += fmt.Sprintf("      DPkts: %v\n", r.DPkts)
	str += fmt.Sprintf("      DOctets: %v\n", r.DOctets)
	str += fmt.Sprintf("      First: %v\n", time.Duration(r.First)*time.Millisecond)
	str += fmt.Sprintf("      Last: %v\n", time.Duration(r.Last)*time.Millisecond)
	str += fmt.Sprintf("      SrcPort: %v\n", r.SrcPort)
	str += fmt.Sprintf("      DstPort: %v\n", r.DstPort)
	str += fmt.Sprintf("      TCPFlags: %v\n", r.TCPFlags)
	str += fmt.Sprintf("      Proto: %v\n", r.Proto)
	str += fmt.Sprintf("      Tos: %v\n", r.Tos)
	str += fmt.Sprintf("      SrcAS: %v\n", r.SrcAS)
	str += fmt.Sprintf("      DstAS: %v\n", r.DstAS)
	str += fmt.Sprintf("      SrcMask: %v\n", r.SrcMask)
	str += fmt.Sprintf("      DstMask: %v\n", r.DstMask)

	return str
}
