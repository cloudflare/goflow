package producer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cloudflare/goflow/decoders/sflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"net"
)

func GetSFlowFlowSamples(packet *sflow.Packet) []interface{} {
	flowSamples := make([]interface{}, 0)
	for _, sample := range packet.Samples {
		switch sample.(type) {
		case sflow.FlowSample:
			flowSamples = append(flowSamples, sample)
		case sflow.ExpandedFlowSample:
			flowSamples = append(flowSamples, sample)
		}
	}
	return flowSamples
}

func ParseSampledHeader(flowMessage *flowmessage.FlowMessage, sampledHeader *sflow.SampledHeader) error {
	data := (*sampledHeader).HeaderData
	switch (*sampledHeader).Protocol {
	case 1: // Ethernet
		etherType := data[12:14]
		var dataTransport []byte
		var nextHeader byte
		var tos byte
		var ttl byte
		var tcpflags byte
		srcIP := net.IP{}
		dstIP := net.IP{}
		offset := 14

		var srcMac uint64
		var dstMac uint64

		var identification uint16
		var fragOffset uint16

		dstMac = binary.BigEndian.Uint64(append([]byte{0, 0}, data[0:6]...))
		srcMac = binary.BigEndian.Uint64(append([]byte{0, 0}, data[6:12]...))
		(*flowMessage).SrcMac = srcMac
		(*flowMessage).DstMac = dstMac

		if etherType[0] == 0x81 && etherType[1] == 0x0 { // VLAN 802.1Q
			(*flowMessage).VlanId = uint32(binary.BigEndian.Uint16(data[14:16]))
			offset += 4
			etherType = data[16:18]
		}

		(*flowMessage).Etype = uint32(binary.BigEndian.Uint16(etherType[0:2]))

		if etherType[0] == 0x8 && etherType[1] == 0x0 { // IPv4
			if len(data) >= offset+36 {
				nextHeader = data[offset+9]
				srcIP = data[offset+12 : offset+16]
				dstIP = data[offset+16 : offset+20]
				dataTransport = data[offset+20 : len(data)]
				tos = data[offset+1]
				ttl = data[offset+8]

				identification = binary.BigEndian.Uint16(data[offset+4 : offset+6])
				fragOffset = binary.BigEndian.Uint16(data[offset+6 : offset+8])
			}
		} else if etherType[0] == 0x86 && etherType[1] == 0xdd { // IPv6
			if len(data) >= offset+40 {
				nextHeader = data[offset+6]
				srcIP = data[offset+8 : offset+24]
				dstIP = data[offset+24 : offset+40]
				dataTransport = data[offset+40 : len(data)]

				tostmp := uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
				tos = uint8(tostmp & 0x0ff0 >> 4)
				ttl = data[offset+7]

				flowLabeltmp := binary.BigEndian.Uint32(data[offset : offset+4])
				(*flowMessage).IPv6FlowLabel = flowLabeltmp & 0xFFFFF
			}
		} else if etherType[0] == 0x8 && etherType[1] == 0x6 { // ARP
		} else {
			return errors.New(fmt.Sprintf("Unknown EtherType: %v\n", etherType))
		}

		if len(dataTransport) >= 4 && (nextHeader == 17 || nextHeader == 6) {
			(*flowMessage).SrcPort = uint32(binary.BigEndian.Uint16(dataTransport[0:2]))
			(*flowMessage).DstPort = uint32(binary.BigEndian.Uint16(dataTransport[2:4]))
		}

		if len(dataTransport) >= 13 && nextHeader == 6 {
			tcpflags = dataTransport[13]
		}

		// ICMP and ICMPv6
		if len(dataTransport) >= 2 && (nextHeader == 1 || nextHeader == 58) {
			(*flowMessage).IcmpType = uint32(dataTransport[0])
			(*flowMessage).IcmpCode = uint32(dataTransport[1])
		}

		(*flowMessage).SrcAddr = srcIP
		(*flowMessage).DstAddr = dstIP
		(*flowMessage).Proto = uint32(nextHeader)
		(*flowMessage).IPTos = uint32(tos)
		(*flowMessage).IPTTL = uint32(ttl)
		(*flowMessage).TCPFlags = uint32(tcpflags)

		(*flowMessage).FragmentId = uint32(identification)
		(*flowMessage).FragmentOffset = uint32(fragOffset)
	}
	return nil
}

func SearchSFlowSamples(samples []interface{}) []*flowmessage.FlowMessage {
	flowMessageSet := make([]*flowmessage.FlowMessage, 0)

	for _, flowSample := range samples {
		var records []sflow.FlowRecord

		flowMessage := &flowmessage.FlowMessage{}
		flowMessage.Type = flowmessage.FlowMessage_SFLOW_5

		switch flowSample := flowSample.(type) {
		case sflow.FlowSample:
			records = flowSample.Records
			flowMessage.SamplingRate = uint64(flowSample.SamplingRate)
			flowMessage.SrcIf = flowSample.Input
			flowMessage.DstIf = flowSample.Output
		case sflow.ExpandedFlowSample:
			records = flowSample.Records
			flowMessage.SamplingRate = uint64(flowSample.SamplingRate)
			flowMessage.SrcIf = flowSample.InputIfValue
			flowMessage.DstIf = flowSample.OutputIfValue
		}

		ipNh := net.IP{}
		ipSrc := net.IP{}
		ipDst := net.IP{}
		flowMessage.Packets = 1
		for _, record := range records {
			switch recordData := record.Data.(type) {
			case sflow.SampledHeader:
				flowMessage.Bytes = uint64(recordData.FrameLength)
				ParseSampledHeader(flowMessage, &recordData)
			case sflow.SampledIPv4:
				ipSrc = recordData.Base.SrcIP
				ipDst = recordData.Base.DstIP
				flowMessage.SrcAddr = ipSrc
				flowMessage.DstAddr = ipDst
				flowMessage.Bytes = uint64(recordData.Base.Length)
				flowMessage.Proto = recordData.Base.Protocol
				flowMessage.SrcPort = recordData.Base.SrcPort
				flowMessage.DstPort = recordData.Base.DstPort
				flowMessage.IPTos = recordData.Tos
				flowMessage.Etype = 0x800
			case sflow.SampledIPv6:
				ipSrc = recordData.Base.SrcIP
				ipDst = recordData.Base.DstIP
				flowMessage.SrcAddr = ipSrc
				flowMessage.DstAddr = ipDst
				flowMessage.Bytes = uint64(recordData.Base.Length)
				flowMessage.Proto = recordData.Base.Protocol
				flowMessage.SrcPort = recordData.Base.SrcPort
				flowMessage.DstPort = recordData.Base.DstPort
				flowMessage.IPTos = recordData.Priority
				flowMessage.Etype = 0x86dd
			case sflow.ExtendedRouter:
				ipNh = recordData.NextHop
				flowMessage.NextHop = ipNh
				flowMessage.SrcNet = recordData.SrcMaskLen
				flowMessage.DstNet = recordData.DstMaskLen
			case sflow.ExtendedGateway:
				ipNh = recordData.NextHop
				flowMessage.NextHop = ipNh
				flowMessage.SrcAS = recordData.SrcAS
				if len(recordData.ASPath) > 0 {
					flowMessage.DstAS = recordData.ASPath[len(recordData.ASPath)-1]
					flowMessage.NextHopAS = recordData.ASPath[0]
					flowMessage.SrcAS = recordData.AS
				} else {
					flowMessage.DstAS = recordData.AS
				}
			case sflow.ExtendedSwitch:
				flowMessage.SrcVlan = recordData.SrcVlan
				flowMessage.DstVlan = recordData.DstVlan
			}
		}
		flowMessageSet = append(flowMessageSet, flowMessage)
	}
	return flowMessageSet
}

func ProcessMessageSFlow(msgDec interface{}) ([]*flowmessage.FlowMessage, error) {
	switch packet := msgDec.(type) {
	case sflow.Packet:
		seqnum := packet.SequenceNumber
		var agent net.IP
		agent = packet.AgentIP

		flowSamples := GetSFlowFlowSamples(&packet)
		flowMessageSet := SearchSFlowSamples(flowSamples)
		for _, fmsg := range flowMessageSet {
			fmsg.SamplerAddress = agent
			fmsg.SequenceNum = seqnum
		}

		return flowMessageSet, nil
	default:
		return []*flowmessage.FlowMessage{}, errors.New("Bad sFlow version")
	}
}
