package producer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cloudflare/goflow/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"net"
	"sync"
	"time"
)

type SamplingRateSystem interface {
	GetSamplingRate(version uint16, obsDomainId uint32) (uint32, error)
	AddSamplingRate(version uint16, obsDomainId uint32, samplingRate uint32)
}

type basicSamplingRateSystem struct {
	sampling     map[uint16]map[uint32]uint32
	samplinglock *sync.RWMutex
}

func CreateSamplingSystem() SamplingRateSystem {
	ts := &basicSamplingRateSystem{
		sampling:     make(map[uint16]map[uint32]uint32),
		samplinglock: &sync.RWMutex{},
	}
	return ts
}

func (s *basicSamplingRateSystem) AddSamplingRate(version uint16, obsDomainId uint32, samplingRate uint32) {
	s.samplinglock.Lock()
	_, exists := s.sampling[version]
	if exists != true {
		s.sampling[version] = make(map[uint32]uint32)
	}
	s.sampling[version][obsDomainId] = samplingRate
	s.samplinglock.Unlock()
}

func (s *basicSamplingRateSystem) GetSamplingRate(version uint16, obsDomainId uint32) (uint32, error) {
	s.samplinglock.RLock()
	samplingVersion, okver := s.sampling[version]
	if okver {
		samplingRate, okid := samplingVersion[obsDomainId]
		if okid {
			s.samplinglock.RUnlock()
			return samplingRate, nil
		}
		s.samplinglock.RUnlock()
		return 0, errors.New("") // TBC
	}
	s.samplinglock.RUnlock()
	return 0, errors.New("") // TBC
}

type SingleSamplingRateSystem struct {
	Sampling uint32
}

func (s *SingleSamplingRateSystem) AddSamplingRate(version uint16, obsDomainId uint32, samplingRate uint32) {
}

func (s *SingleSamplingRateSystem) GetSamplingRate(version uint16, obsDomainId uint32) (uint32, error) {
	return s.Sampling, nil
}

func NetFlowLookFor(dataFields []netflow.DataField, typeId uint16) (bool, interface{}) {
	for _, dataField := range dataFields {
		if dataField.Type == typeId {
			return true, dataField.Value
		}
	}
	return false, nil
}

func NetFlowPopulate(dataFields []netflow.DataField, typeId uint16, addr interface{}) bool {
	exists, value := NetFlowLookFor(dataFields, typeId)
	if exists && value != nil {
		valueBytes, ok := value.([]byte)
		valueReader := bytes.NewReader(valueBytes)
		if ok {
			switch addrt := addr.(type) {
			case *(net.IP):
				*addrt = valueBytes
			case *(time.Time):
				t := uint64(0)
				binary.Read(valueReader, binary.BigEndian, &t)
				t64 := int64(t / 1000)
				*addrt = time.Unix(t64, 0)
			default:
				binary.Read(valueReader, binary.BigEndian, addr)
			}
		}
	}
	return exists
}

func DecodeUNumber(b []byte, out interface{}) error {
	var o uint64
	l := len(b)
	switch l {
	case 1:
		o = uint64(b[0])
	case 2:
		o = uint64(binary.BigEndian.Uint16(b))
	case 4:
		o = uint64(binary.BigEndian.Uint32(b))
	case 8:
		o = binary.BigEndian.Uint64(b)
	default:
		if l < 8 {
			var iter uint
			for i := range b {
				o |= uint64(b[i]) << uint(8*(uint(l)-iter-1))
				iter++
			}
		} else {
			return errors.New(fmt.Sprintf("Non-regular number of bytes for a number: %v", l))
		}
	}
	switch t := out.(type) {
	case *byte:
		*t = byte(o)
	case *uint16:
		*t = uint16(o)
	case *uint32:
		*t = uint32(o)
	case *uint64:
		*t = o
	default:
		return errors.New("The parameter is not a pointer to a byte/uint16/uint32/uint64 structure")
	}
	return nil
}

func ConvertNetFlowDataSet(version uint16, baseTime uint32, uptime uint32, record []netflow.DataField) *flowmessage.FlowMessage {
	flowMessage := &flowmessage.FlowMessage{}
	var time uint64

	if version == 9 {
		flowMessage.Type = flowmessage.FlowMessage_NETFLOW_V9
	} else if version == 10 {
		flowMessage.Type = flowmessage.FlowMessage_IPFIX
	}

	for i := range record {
		df := record[i]

		v, ok := df.Value.([]byte)
		if !ok {
			continue
		}

		switch df.Type {

		// Statistics
		case netflow.NFV9_FIELD_IN_BYTES:
			DecodeUNumber(v, &(flowMessage.Bytes))
		case netflow.NFV9_FIELD_IN_PKTS:
			DecodeUNumber(v, &(flowMessage.Packets))
		case netflow.NFV9_FIELD_OUT_BYTES:
			DecodeUNumber(v, &(flowMessage.Bytes))
		case netflow.NFV9_FIELD_OUT_PKTS:
			DecodeUNumber(v, &(flowMessage.Packets))

		// L4
		case netflow.NFV9_FIELD_L4_SRC_PORT:
			DecodeUNumber(v, &(flowMessage.SrcPort))
		case netflow.NFV9_FIELD_L4_DST_PORT:
			DecodeUNumber(v, &(flowMessage.DstPort))
		case netflow.NFV9_FIELD_PROTOCOL:
			DecodeUNumber(v, &(flowMessage.Proto))

		// Network
		case netflow.NFV9_FIELD_SRC_AS:
			DecodeUNumber(v, &(flowMessage.SrcAS))
		case netflow.NFV9_FIELD_DST_AS:
			DecodeUNumber(v, &(flowMessage.DstAS))

		// Interfaces
		case netflow.NFV9_FIELD_INPUT_SNMP:
			DecodeUNumber(v, &(flowMessage.SrcIf))
		case netflow.NFV9_FIELD_OUTPUT_SNMP:
			DecodeUNumber(v, &(flowMessage.DstIf))

		case netflow.NFV9_FIELD_FORWARDING_STATUS:
			DecodeUNumber(v, &(flowMessage.ForwardingStatus))
		case netflow.NFV9_FIELD_SRC_TOS:
			DecodeUNumber(v, &(flowMessage.IPTos))
		case netflow.NFV9_FIELD_TCP_FLAGS:
			DecodeUNumber(v, &(flowMessage.TCPFlags))
		case netflow.NFV9_FIELD_MIN_TTL:
			DecodeUNumber(v, &(flowMessage.IPTTL))

		// IP
		case netflow.NFV9_FIELD_IPV4_SRC_ADDR:
			flowMessage.SrcAddr = v
			flowMessage.Etype = 0x800
		case netflow.NFV9_FIELD_IPV4_DST_ADDR:
			flowMessage.DstAddr = v
			flowMessage.Etype = 0x800

		case netflow.NFV9_FIELD_SRC_MASK:
			DecodeUNumber(v, &(flowMessage.SrcNet))
		case netflow.NFV9_FIELD_DST_MASK:
			DecodeUNumber(v, &(flowMessage.DstNet))

		case netflow.NFV9_FIELD_IPV6_SRC_ADDR:
			flowMessage.SrcAddr = v
			flowMessage.Etype = 0x86dd
		case netflow.NFV9_FIELD_IPV6_DST_ADDR:
			flowMessage.DstAddr = v
			flowMessage.Etype = 0x86dd

		case netflow.NFV9_FIELD_IPV6_SRC_MASK:
			DecodeUNumber(v, &(flowMessage.SrcNet))
		case netflow.NFV9_FIELD_IPV6_DST_MASK:
			DecodeUNumber(v, &(flowMessage.DstNet))

		case netflow.NFV9_FIELD_IPV4_NEXT_HOP:
			flowMessage.NextHop = v
		case netflow.NFV9_FIELD_BGP_IPV4_NEXT_HOP:
			flowMessage.NextHop = v

		case netflow.NFV9_FIELD_IPV6_NEXT_HOP:
			flowMessage.NextHop = v
		case netflow.NFV9_FIELD_BGP_IPV6_NEXT_HOP:
			flowMessage.NextHop = v

		// ICMP
		case netflow.NFV9_FIELD_ICMP_TYPE:
			var icmpTypeCode uint16
			DecodeUNumber(v, &icmpTypeCode)
			flowMessage.IcmpType = uint32(icmpTypeCode >> 8)
			flowMessage.IcmpCode = uint32(icmpTypeCode & 0xff)
		case netflow.IPFIX_FIELD_icmpTypeCodeIPv6:
			var icmpTypeCode uint16
			DecodeUNumber(v, &icmpTypeCode)
			flowMessage.IcmpType = uint32(icmpTypeCode >> 8)
			flowMessage.IcmpCode = uint32(icmpTypeCode & 0xff)
		case netflow.IPFIX_FIELD_icmpTypeIPv4:
			DecodeUNumber(v, &(flowMessage.IcmpType))
		case netflow.IPFIX_FIELD_icmpTypeIPv6:
			DecodeUNumber(v, &(flowMessage.IcmpType))
		case netflow.IPFIX_FIELD_icmpCodeIPv4:
			DecodeUNumber(v, &(flowMessage.IcmpCode))
		case netflow.IPFIX_FIELD_icmpCodeIPv6:
			DecodeUNumber(v, &(flowMessage.IcmpCode))

		// Mac
		case netflow.NFV9_FIELD_IN_SRC_MAC:
			DecodeUNumber(v, &(flowMessage.SrcMac))
		case netflow.NFV9_FIELD_OUT_DST_MAC:
			DecodeUNumber(v, &(flowMessage.DstMac))

		case netflow.NFV9_FIELD_SRC_VLAN:
			DecodeUNumber(v, &(flowMessage.VlanId))
			DecodeUNumber(v, &(flowMessage.SrcVlan))
		case netflow.NFV9_FIELD_DST_VLAN:
			DecodeUNumber(v, &(flowMessage.DstVlan))

		case netflow.IPFIX_FIELD_ingressVRFID:
			DecodeUNumber(v, &(flowMessage.IngressVrfID))
		case netflow.IPFIX_FIELD_egressVRFID:
			DecodeUNumber(v, &(flowMessage.EgressVrfID))

		case netflow.NFV9_FIELD_IPV4_IDENT:
			DecodeUNumber(v, &(flowMessage.FragmentId))
		case netflow.NFV9_FIELD_FRAGMENT_OFFSET:
			DecodeUNumber(v, &(flowMessage.FragmentOffset))

		case netflow.NFV9_FIELD_IPV6_FLOW_LABEL:
			DecodeUNumber(v, &(flowMessage.IPv6FlowLabel))

		case netflow.IPFIX_FIELD_biflowDirection:
			DecodeUNumber(v, &(flowMessage.BiFlowDirection))

		case netflow.NFV9_FIELD_DIRECTION:
			DecodeUNumber(v, &(flowMessage.FlowDirection))

		default:
			if version == 9 {
				// NetFlow v9 time works with a differential based on router's uptime
				switch df.Type {
				case netflow.NFV9_FIELD_FIRST_SWITCHED:
					var timeFirstSwitched uint32
					DecodeUNumber(v, &timeFirstSwitched)
					timeDiff := (uptime - timeFirstSwitched) / 1000
					flowMessage.TimeFlowStart = uint64(baseTime - timeDiff)
				case netflow.NFV9_FIELD_LAST_SWITCHED:
					var timeLastSwitched uint32
					DecodeUNumber(v, &timeLastSwitched)
					timeDiff := (uptime - timeLastSwitched) / 1000
					flowMessage.TimeFlowEnd = uint64(baseTime - timeDiff)
				}
			} else if version == 10 {
				switch df.Type {
				case netflow.IPFIX_FIELD_flowStartSeconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowStart = time
				case netflow.IPFIX_FIELD_flowStartMilliseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowStart = time / 1000
				case netflow.IPFIX_FIELD_flowStartMicroseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowStart = time / 1000000
				case netflow.IPFIX_FIELD_flowStartNanoseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowStart = time / 1000000000
				case netflow.IPFIX_FIELD_flowEndSeconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowEnd = time
				case netflow.IPFIX_FIELD_flowEndMilliseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowEnd = time / 1000
				case netflow.IPFIX_FIELD_flowEndMicroseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowEnd = time / 1000000
				case netflow.IPFIX_FIELD_flowEndNanoseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlowEnd = time / 1000000000
				}
			}
		}

	}

	return flowMessage
}

func SearchNetFlowDataSetsRecords(version uint16, baseTime uint32, uptime uint32, dataRecords []netflow.DataRecord) []*flowmessage.FlowMessage {
	flowMessageSet := make([]*flowmessage.FlowMessage, 0)
	for _, record := range dataRecords {
		fmsg := ConvertNetFlowDataSet(version, baseTime, uptime, record.Values)
		if fmsg != nil {
			flowMessageSet = append(flowMessageSet, fmsg)
		}
	}
	return flowMessageSet
}

func SearchNetFlowDataSets(version uint16, baseTime uint32, uptime uint32, dataFlowSet []netflow.DataFlowSet) []*flowmessage.FlowMessage {
	flowMessageSet := make([]*flowmessage.FlowMessage, 0)
	for _, dataFlowSetItem := range dataFlowSet {
		fmsg := SearchNetFlowDataSetsRecords(version, baseTime, uptime, dataFlowSetItem.Records)
		if fmsg != nil {
			flowMessageSet = append(flowMessageSet, fmsg...)
		}
	}
	return flowMessageSet
}

func SearchNetFlowOptionDataSets(dataFlowSet []netflow.OptionsDataFlowSet) (uint32, bool) {
	var samplingRate uint32
	var found bool
	for _, dataFlowSetItem := range dataFlowSet {
		for _, record := range dataFlowSetItem.Records {
			b := NetFlowPopulate(record.OptionsValues, 305, &samplingRate)
			if b {
				return samplingRate, b
			}
			b = NetFlowPopulate(record.OptionsValues, 50, &samplingRate)
			if b {
				return samplingRate, b
			}
			b = NetFlowPopulate(record.OptionsValues, 34, &samplingRate)
			if b {
				return samplingRate, b
			}
		}
	}
	return samplingRate, found
}

func SplitNetFlowSets(packetNFv9 netflow.NFv9Packet) ([]netflow.DataFlowSet, []netflow.TemplateFlowSet, []netflow.NFv9OptionsTemplateFlowSet, []netflow.OptionsDataFlowSet) {
	dataFlowSet := make([]netflow.DataFlowSet, 0)
	templatesFlowSet := make([]netflow.TemplateFlowSet, 0)
	optionsTemplatesFlowSet := make([]netflow.NFv9OptionsTemplateFlowSet, 0)
	optionsDataFlowSet := make([]netflow.OptionsDataFlowSet, 0)
	for _, flowSet := range packetNFv9.FlowSets {
		switch flowSet.(type) {
		case netflow.TemplateFlowSet:
			templatesFlowSet = append(templatesFlowSet, flowSet.(netflow.TemplateFlowSet))
		case netflow.NFv9OptionsTemplateFlowSet:
			optionsTemplatesFlowSet = append(optionsTemplatesFlowSet, flowSet.(netflow.NFv9OptionsTemplateFlowSet))
		case netflow.DataFlowSet:
			dataFlowSet = append(dataFlowSet, flowSet.(netflow.DataFlowSet))
		case netflow.OptionsDataFlowSet:
			optionsDataFlowSet = append(optionsDataFlowSet, flowSet.(netflow.OptionsDataFlowSet))
		}
	}
	return dataFlowSet, templatesFlowSet, optionsTemplatesFlowSet, optionsDataFlowSet
}

func SplitIPFIXSets(packetIPFIX netflow.IPFIXPacket) ([]netflow.DataFlowSet, []netflow.TemplateFlowSet, []netflow.IPFIXOptionsTemplateFlowSet, []netflow.OptionsDataFlowSet) {
	dataFlowSet := make([]netflow.DataFlowSet, 0)
	templatesFlowSet := make([]netflow.TemplateFlowSet, 0)
	optionsTemplatesFlowSet := make([]netflow.IPFIXOptionsTemplateFlowSet, 0)
	optionsDataFlowSet := make([]netflow.OptionsDataFlowSet, 0)
	for _, flowSet := range packetIPFIX.FlowSets {
		switch flowSet.(type) {
		case netflow.TemplateFlowSet:
			templatesFlowSet = append(templatesFlowSet, flowSet.(netflow.TemplateFlowSet))
		case netflow.IPFIXOptionsTemplateFlowSet:
			optionsTemplatesFlowSet = append(optionsTemplatesFlowSet, flowSet.(netflow.IPFIXOptionsTemplateFlowSet))
		case netflow.DataFlowSet:
			dataFlowSet = append(dataFlowSet, flowSet.(netflow.DataFlowSet))
		case netflow.OptionsDataFlowSet:
			optionsDataFlowSet = append(optionsDataFlowSet, flowSet.(netflow.OptionsDataFlowSet))
		}
	}
	return dataFlowSet, templatesFlowSet, optionsTemplatesFlowSet, optionsDataFlowSet
}

// Convert a NetFlow datastructure to a FlowMessage protobuf
// Does not put sampling rate
func ProcessMessageNetFlow(msgDec interface{}, samplingRateSys SamplingRateSystem) ([]*flowmessage.FlowMessage, error) {
	seqnum := uint32(0)
	var baseTime uint32
	var uptime uint32

	flowMessageSet := make([]*flowmessage.FlowMessage, 0)

	switch msgDecConv := msgDec.(type) {
	case netflow.NFv9Packet:
		dataFlowSet, _, _, optionDataFlowSet := SplitNetFlowSets(msgDecConv)

		seqnum = msgDecConv.SequenceNumber
		baseTime = msgDecConv.UnixSeconds
		uptime = msgDecConv.SystemUptime
		obsDomainId := msgDecConv.SourceId

		flowMessageSet = SearchNetFlowDataSets(9, baseTime, uptime, dataFlowSet)
		samplingRate, found := SearchNetFlowOptionDataSets(optionDataFlowSet)
		if samplingRateSys != nil {
			if found {
				samplingRateSys.AddSamplingRate(9, obsDomainId, samplingRate)
			} else {
				samplingRate, _ = samplingRateSys.GetSamplingRate(9, obsDomainId)
			}
		}
		for _, fmsg := range flowMessageSet {
			fmsg.SequenceNum = seqnum
			fmsg.SamplingRate = uint64(samplingRate)
		}
	case netflow.IPFIXPacket:
		dataFlowSet, _, _, optionDataFlowSet := SplitIPFIXSets(msgDecConv)

		seqnum = msgDecConv.SequenceNumber
		baseTime = msgDecConv.ExportTime
		obsDomainId := msgDecConv.ObservationDomainId

		flowMessageSet = SearchNetFlowDataSets(10, baseTime, uptime, dataFlowSet)

		samplingRate, found := SearchNetFlowOptionDataSets(optionDataFlowSet)
		if samplingRateSys != nil {
			if found {
				samplingRateSys.AddSamplingRate(10, obsDomainId, samplingRate)
			} else {
				samplingRate, _ = samplingRateSys.GetSamplingRate(10, obsDomainId)
			}
		}
		for _, fmsg := range flowMessageSet {
			fmsg.SequenceNum = seqnum
			fmsg.SamplingRate = uint64(samplingRate)
		}
	default:
		return flowMessageSet, errors.New("Bad NetFlow/IPFIX version")
	}

	return flowMessageSet, nil
}
