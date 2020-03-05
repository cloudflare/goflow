package producer

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/cloudflare/goflow/v3/decoders/sflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
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

type SFlowProducerConfig struct {
	DecodeGRE bool
}

func ParseSampledHeader(flowMessage *flowmessage.FlowMessage, sampledHeader *sflow.SampledHeader) error {
	return ParseSampledHeaderConfig(flowMessage, sampledHeader, nil)
}

func ParseSampledHeaderConfig(flowMessage *flowmessage.FlowMessage, sampledHeader *sflow.SampledHeader, config *SFlowProducerConfig) error {
	var decodeGRE bool
	if config != nil {
		decodeGRE = config.DecodeGRE
	}

	data := (*sampledHeader).HeaderData
	switch (*sampledHeader).Protocol {
	case 1: // Ethernet
		var hasPPP bool
		var pppAddressControl uint16
		var hasMPLS bool
		var countMpls uint32
		var firstLabelMpls uint32
		var firstTtlMpls uint8
		var secondLabelMpls uint32
		var secondTtlMpls uint8
		var thirdLabelMpls uint32
		var thirdTtlMpls uint8
		var lastLabelMpls uint32
		var lastTtlMpls uint8

		var hasEncap bool
		var nextHeader byte
		var nextHeaderEncap byte
		var tcpflags byte
		srcIP := net.IP{}
		dstIP := net.IP{}
		srcIPEncap := net.IP{}
		dstIPEncap := net.IP{}
		offset := 14

		var srcMac uint64
		var dstMac uint64

		var tos byte
		var ttl byte
		var identification uint16
		var fragOffset uint16
		var flowLabel uint32

		var tosEncap byte
		var ttlEncap byte
		var identificationEncap uint16
		var fragOffsetEncap uint16
		var flowLabelEncap uint32

		var srcPort uint16
		var dstPort uint16

		etherType := data[12:14]
		etherTypeEncap := []byte{0, 0}

		dstMac = binary.BigEndian.Uint64(append([]byte{0, 0}, data[0:6]...))
		srcMac = binary.BigEndian.Uint64(append([]byte{0, 0}, data[6:12]...))
		(*flowMessage).SrcMac = srcMac
		(*flowMessage).DstMac = dstMac

		encap := true
		iterations := 0
		for encap && iterations <= 1 {
			encap = false

			if etherType[0] == 0x81 && etherType[1] == 0x0 { // VLAN 802.1Q
				(*flowMessage).VlanId = uint32(binary.BigEndian.Uint16(data[14:16]))
				offset += 4
				etherType = data[16:18]
			}

			if etherType[0] == 0x88 && etherType[1] == 0x47 { // MPLS
				iterateMpls := true
				hasMPLS = true
				for iterateMpls {
					if len(data) < offset+5 {
						iterateMpls = false
						break
					}
					label := binary.BigEndian.Uint32(append([]byte{0}, data[offset:offset+3]...)) >> 4
					//exp := data[offset+2] > 1
					bottom := data[offset+2] & 1
					mplsTtl := data[offset+3]
					offset += 4

					if bottom == 1 || label <= 15 || offset > len(data) {
						if data[offset]&0xf0>>4 == 4 {
							etherType = []byte{0x8, 0x0}
						} else if data[offset]&0xf0>>4 == 6 {
							etherType = []byte{0x86, 0xdd}
						}
						iterateMpls = false
					}

					if countMpls == 0 {
						firstLabelMpls = label
						firstTtlMpls = mplsTtl
					} else if countMpls == 1 {
						secondLabelMpls = label
						secondTtlMpls = mplsTtl
					} else if countMpls == 2 {
						thirdLabelMpls = label
						thirdTtlMpls = mplsTtl
					} else {
						lastLabelMpls = label
						lastTtlMpls = mplsTtl
					}
					countMpls++
				}
			}

			if etherType[0] == 0x8 && etherType[1] == 0x0 { // IPv4
				if len(data) >= offset+20 {
					nextHeader = data[offset+9]
					srcIP = data[offset+12 : offset+16]
					dstIP = data[offset+16 : offset+20]
					tos = data[offset+1]
					ttl = data[offset+8]

					identification = binary.BigEndian.Uint16(data[offset+4 : offset+6])
					fragOffset = binary.BigEndian.Uint16(data[offset+6 : offset+8])

					offset += 20
				}
			} else if etherType[0] == 0x86 && etherType[1] == 0xdd { // IPv6
				if len(data) >= offset+40 {
					nextHeader = data[offset+6]
					srcIP = data[offset+8 : offset+24]
					dstIP = data[offset+24 : offset+40]

					tostmp := uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
					tos = uint8(tostmp & 0x0ff0 >> 4)
					ttl = data[offset+7]

					flowLabel = binary.BigEndian.Uint32(data[offset : offset+4])

					offset += 40

				}
			} else if etherType[0] == 0x8 && etherType[1] == 0x6 { // ARP
			} /*else {
				return errors.New(fmt.Sprintf("Unknown EtherType: %v\n", etherType))
			} */

			if len(data) >= offset+4 && (nextHeader == 17 || nextHeader == 6) {
				srcPort = binary.BigEndian.Uint16(data[offset+0 : offset+2])
				dstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			}

			if len(data) >= offset+13 && nextHeader == 6 {
				tcpflags = data[offset+13]
			}

			// ICMP and ICMPv6
			if len(data) >= offset+2 && (nextHeader == 1 || nextHeader == 58) {
				(*flowMessage).IcmpType = uint32(data[offset+0])
				(*flowMessage).IcmpCode = uint32(data[offset+1])
			}

			// GRE
			if len(data) >= offset+4 && nextHeader == 47 {
				etherTypeEncap = data[offset+2 : offset+4]
				offset += 4
				if (etherTypeEncap[0] == 0x8 && etherTypeEncap[1] == 0x0) ||
					(etherTypeEncap[0] == 0x86 && etherTypeEncap[1] == 0xdd) {
					encap = true
					hasEncap = true
				}
				if etherTypeEncap[0] == 0x88 && etherTypeEncap[1] == 0x0b && len(data) >= offset+12 {
					offset += 8
					encap = true
					hasPPP = true
					pppAddressControl = binary.BigEndian.Uint16(data[offset : offset+2])
					pppEtherType := data[offset+2 : offset+4]
					if pppEtherType[0] == 0x0 && pppEtherType[1] == 0x21 {
						etherTypeEncap = []byte{0x8, 0x00}
						hasEncap = true
					} else if pppEtherType[0] == 0x0 && pppEtherType[1] == 0x57 {
						etherTypeEncap = []byte{0x86, 0xdd}
						hasEncap = true
					}
					offset += 4

				}

				if hasEncap {
					srcIPEncap = srcIP
					dstIPEncap = dstIP

					nextHeaderEncap = nextHeader
					tosEncap = tos
					ttlEncap = ttl
					identificationEncap = identification
					fragOffsetEncap = fragOffset
					flowLabelEncap = flowLabel

					etherTypeEncapTmp := etherTypeEncap
					etherTypeEncap = etherType
					etherType = etherTypeEncapTmp
				}

			}
			iterations++
		}

		if !decodeGRE && hasEncap {
			//fmt.Printf("DEOCDE %v -> %v || %v -> %v\n", net.IP(srcIPEncap), net.IP(dstIPEncap), net.IP(srcIP), net.IP(dstIP))
			tmpSrc := srcIPEncap
			tmpDst := dstIPEncap
			srcIPEncap = srcIP
			dstIPEncap = dstIP
			srcIP = tmpSrc
			dstIP = tmpDst

			tmpNextHeader := nextHeaderEncap
			nextHeaderEncap = nextHeader
			nextHeader = tmpNextHeader

			tosTmp := tosEncap
			tosEncap = tos
			tos = tosTmp

			ttlTmp := ttlEncap
			ttlEncap = ttl
			ttl = ttlTmp

			identificationTmp := identificationEncap
			identificationEncap = identification
			identification = identificationTmp

			fragOffsetTmp := fragOffsetEncap
			fragOffsetEncap = fragOffset
			fragOffset = fragOffsetTmp

			flowLabelTmp := flowLabelEncap
			flowLabelEncap = flowLabel
			flowLabel = flowLabelTmp
		}

		(*flowMessage).HasPPP = hasPPP
		(*flowMessage).PPPAddressControl = uint32(pppAddressControl)

		(*flowMessage).HasMPLS = hasMPLS
		(*flowMessage).MPLSCount = countMpls
		(*flowMessage).MPLS1Label = firstLabelMpls
		(*flowMessage).MPLS1TTL = uint32(firstTtlMpls)
		(*flowMessage).MPLS2Label = secondLabelMpls
		(*flowMessage).MPLS2TTL = uint32(secondTtlMpls)
		(*flowMessage).MPLS3Label = thirdLabelMpls
		(*flowMessage).MPLS3TTL = uint32(thirdTtlMpls)
		(*flowMessage).MPLSLastLabel = lastLabelMpls
		(*flowMessage).MPLSLastTTL = uint32(lastTtlMpls)

		(*flowMessage).HasEncap = hasEncap
		(*flowMessage).ProtoEncap = uint32(nextHeaderEncap)
		(*flowMessage).SrcAddrEncap = srcIPEncap
		(*flowMessage).DstAddrEncap = dstIPEncap
		(*flowMessage).EtypeEncap = uint32(binary.BigEndian.Uint16(etherTypeEncap[0:2]))

		(*flowMessage).IPTosEncap = uint32(tosEncap)
		(*flowMessage).IPTTLEncap = uint32(ttlEncap)
		(*flowMessage).FragmentIdEncap = uint32(identificationEncap)
		(*flowMessage).FragmentOffsetEncap = uint32(fragOffsetEncap)
		(*flowMessage).IPv6FlowLabelEncap = flowLabelEncap & 0xFFFFF

		(*flowMessage).Etype = uint32(binary.BigEndian.Uint16(etherType[0:2]))
		(*flowMessage).IPv6FlowLabel = flowLabel & 0xFFFFF

		(*flowMessage).SrcPort = uint32(srcPort)
		(*flowMessage).DstPort = uint32(dstPort)

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
	return SearchSFlowSamples(samples)
}

func SearchSFlowSamplesConfig(samples []interface{}, config *SFlowProducerConfig) []*flowmessage.FlowMessage {
	flowMessageSet := make([]*flowmessage.FlowMessage, 0)

	for _, flowSample := range samples {
		var records []sflow.FlowRecord

		flowMessage := &flowmessage.FlowMessage{}
		flowMessage.Type = flowmessage.FlowMessage_SFLOW_5

		switch flowSample := flowSample.(type) {
		case sflow.FlowSample:
			records = flowSample.Records
			flowMessage.SamplingRate = uint64(flowSample.SamplingRate)
			flowMessage.InIf = flowSample.Input
			flowMessage.OutIf = flowSample.Output
		case sflow.ExpandedFlowSample:
			records = flowSample.Records
			flowMessage.SamplingRate = uint64(flowSample.SamplingRate)
			flowMessage.InIf = flowSample.InputIfValue
			flowMessage.OutIf = flowSample.OutputIfValue
		}

		ipNh := net.IP{}
		ipSrc := net.IP{}
		ipDst := net.IP{}
		flowMessage.Packets = 1
		for _, record := range records {
			switch recordData := record.Data.(type) {
			case sflow.SampledHeader:
				flowMessage.Bytes = uint64(recordData.FrameLength)
				ParseSampledHeaderConfig(flowMessage, &recordData, config)
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
	return ProcessMessageSFlowConfig(msgDec, nil)
}

func ProcessMessageSFlowConfig(msgDec interface{}, config *SFlowProducerConfig) ([]*flowmessage.FlowMessage, error) {
	switch packet := msgDec.(type) {
	case sflow.Packet:
		seqnum := packet.SequenceNumber
		var agent net.IP
		agent = packet.AgentIP

		flowSamples := GetSFlowFlowSamples(&packet)
		flowMessageSet := SearchSFlowSamplesConfig(flowSamples, config)
		for _, fmsg := range flowMessageSet {
			fmsg.SamplerAddress = agent
			fmsg.SequenceNum = seqnum
		}

		return flowMessageSet, nil
	default:
		return []*flowmessage.FlowMessage{}, errors.New("Bad sFlow version")
	}
}
