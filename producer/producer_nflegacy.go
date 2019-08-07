package producer

import (
	"encoding/binary"
	"errors"
	"github.com/cloudflare/goflow/decoders/netflowlegacy"
	flowmessage "github.com/cloudflare/goflow/pb"
	"net"
)

func ConvertNetFlowLegacyRecord(baseTime uint32, uptime uint32, record netflowlegacy.RecordsNetFlowV5) *flowmessage.FlowMessage {
	flowMessage := &flowmessage.FlowMessage{}

	flowMessage.Type = flowmessage.FlowMessage_NETFLOW_V5

	timeDiffFirst := (uptime - record.First) / 1000
	timeDiffLast := (uptime - record.Last) / 1000
	flowMessage.TimeFlowStart = uint64(baseTime - timeDiffFirst)
	flowMessage.TimeFlowEnd = uint64(baseTime - timeDiffLast)

	v := make(net.IP, 4)
	binary.BigEndian.PutUint32(v, record.NextHop)
	flowMessage.NextHop = v
	v = make(net.IP, 4)
	binary.BigEndian.PutUint32(v, record.SrcAddr)
	flowMessage.SrcAddr = v
	v = make(net.IP, 4)
	binary.BigEndian.PutUint32(v, record.DstAddr)
	flowMessage.DstAddr = v

	flowMessage.Etype = 0x800
	flowMessage.SrcAS = uint32(record.SrcAS)
	flowMessage.DstAS = uint32(record.DstAS)
	flowMessage.SrcNet = uint32(record.SrcMask)
	flowMessage.DstNet = uint32(record.DstMask)
	flowMessage.Proto = uint32(record.Proto)
	flowMessage.TCPFlags = uint32(record.TCPFlags)
	flowMessage.IPTos = uint32(record.Tos)
	flowMessage.SrcIf = uint32(record.Input)
	flowMessage.DstIf = uint32(record.Output)
	flowMessage.SrcPort = uint32(record.SrcPort)
	flowMessage.DstPort = uint32(record.DstPort)
	flowMessage.Packets = uint64(record.DPkts)
	flowMessage.Bytes = uint64(record.DOctets)

	return flowMessage
}

func SearchNetFlowLegacyRecords(baseTime uint32, uptime uint32, dataRecords []netflowlegacy.RecordsNetFlowV5) []*flowmessage.FlowMessage {
	flowMessageSet := make([]*flowmessage.FlowMessage, 0)
	for _, record := range dataRecords {
		fmsg := ConvertNetFlowLegacyRecord(baseTime, uptime, record)
		if fmsg != nil {
			flowMessageSet = append(flowMessageSet, fmsg)
		}
	}
	return flowMessageSet
}

func ProcessMessageNetFlowLegacy(msgDec interface{}) ([]*flowmessage.FlowMessage, error) {
	switch packet := msgDec.(type) {
	case netflowlegacy.PacketNetFlowV5:
		seqnum := packet.FlowSequence
		samplingRate := packet.SamplingInterval
		baseTime := packet.UnixSecs
		uptime := packet.SysUptime

		flowMessageSet := SearchNetFlowLegacyRecords(baseTime, uptime, packet.Records)
		for _, fmsg := range flowMessageSet {
			fmsg.SequenceNum = seqnum
			fmsg.SamplingRate = uint64(samplingRate)
		}

		return flowMessageSet, nil
	default:
		return []*flowmessage.FlowMessage{}, errors.New("Bad NetFlow v5 version")
	}
}
