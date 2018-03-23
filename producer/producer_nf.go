package producer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/cloudflare/goflow/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"strconv"
	"sync"
	"time"
)

var (
	NetFlowStats = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_nf_count",
			Help: "NetFlows processed.",
		},
		[]string{"router", "version"},
	)
	NetFlowErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_nf_errors_count",
			Help: "NetFlows processed errors.",
		},
		[]string{"router", "version", "error"},
	)
	NetFlowSetRecordsStatsSum = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_nf_flowset_records_sum",
			Help: "NetFlows FlowSets sum of records.",
		},
		[]string{"router", "version", "type"}, // data-template, data, opts...
	)
	NetFlowSetStatsSum = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_nf_flowset_sum",
			Help: "NetFlows FlowSets sum.",
		},
		[]string{"router", "version", "type"}, // data-template, data, opts...
	)
	NetFlowTimeStatsSum = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "flow_process_nf_delay_summary_seconds",
			Help:       "NetFlows time difference between time of flow and processing.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"router", "version"},
	)
	NetFlowTemplatesStats = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_nf_templates_count",
			Help: "NetFlows Template count.",
		},
		[]string{"router", "version", "obs_domain_id", "type"}, // options/template
	)
)

type SamplingRateMap map[string]map[uint32]uint64
type TemplateMap map[string]map[uint32]map[uint16]bool

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
	//log.Printf("Populate: %v %v %v\n", typeId, exists, value)
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

func ConvertNetFlowDataSet(router net.IP, version uint16, seqnum uint32, sampling uint64, baseTime uint32, uptime uint32, record []netflow.DataField) *flowmessage.FlowMessage {
	routerStr := router.String()
	flowMessage := &flowmessage.FlowMessage{
		SamplingRate: sampling,
		TimeRecvd:    uint64(time.Now().Unix()),
	}
	flowMessage.RouterAddr = router
	var time uint64

	if version == 9 {
		flowMessage.Type = flowmessage.FlowMessage_NFV9
	} else if version == 10 {
		flowMessage.Type = flowmessage.FlowMessage_IPFIX
	}
	flowMessage.SequenceNum = seqnum

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
			flowMessage.IPversion = flowmessage.FlowMessage_IPv4
			flowMessage.SrcIP = v
		case netflow.NFV9_FIELD_IPV4_DST_ADDR:
			flowMessage.IPversion = flowmessage.FlowMessage_IPv4
			flowMessage.DstIP = v

		case netflow.NFV9_FIELD_SRC_MASK:
			DecodeUNumber(v, &(flowMessage.SrcNet))
		case netflow.NFV9_FIELD_DST_MASK:
			DecodeUNumber(v, &(flowMessage.DstNet))

		case netflow.NFV9_FIELD_IPV6_SRC_ADDR:
			flowMessage.IPversion = flowmessage.FlowMessage_IPv6
			flowMessage.SrcIP = v
		case netflow.NFV9_FIELD_IPV6_DST_ADDR:
			flowMessage.IPversion = flowmessage.FlowMessage_IPv6
			flowMessage.DstIP = v

		case netflow.NFV9_FIELD_IPV6_SRC_MASK:
			DecodeUNumber(v, &(flowMessage.SrcNet))
		case netflow.NFV9_FIELD_IPV6_DST_MASK:
			DecodeUNumber(v, &(flowMessage.DstNet))

		case netflow.NFV9_FIELD_IPV4_NEXT_HOP:
			flowMessage.IPversion = flowmessage.FlowMessage_IPv4
			flowMessage.NextHop = v
		case netflow.NFV9_FIELD_BGP_IPV4_NEXT_HOP:
			flowMessage.IPversion = flowmessage.FlowMessage_IPv4
			flowMessage.NextHop = v

		case netflow.NFV9_FIELD_IPV6_NEXT_HOP:
			flowMessage.IPversion = flowmessage.FlowMessage_IPv6
			flowMessage.NextHop = v
		case netflow.NFV9_FIELD_BGP_IPV6_NEXT_HOP:
			flowMessage.IPversion = flowmessage.FlowMessage_IPv6
			flowMessage.NextHop = v

		// Mac
		case netflow.NFV9_FIELD_IN_SRC_MAC:
			DecodeUNumber(v, &(flowMessage.SrcMac))
		case netflow.NFV9_FIELD_OUT_DST_MAC:
			DecodeUNumber(v, &(flowMessage.DstMac))

		case netflow.NFV9_FIELD_SRC_VLAN:
			DecodeUNumber(v, &(flowMessage.VlanId))

		default:
			if version == 9 {
				// NetFlow v9 time works with a differential based on router's uptime
				switch df.Type {
				case netflow.NFV9_FIELD_LAST_SWITCHED:
					var timeLastSwitched uint32
					DecodeUNumber(v, &timeLastSwitched)
					timeDiff := (uptime - timeLastSwitched) / 1000
					flowMessage.TimeFlow = uint64(baseTime - timeDiff)
				}
			} else if version == 10 {
				switch df.Type {
				case netflow.IPFIX_FIELD_flowEndSeconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlow = time
				case netflow.IPFIX_FIELD_flowEndMilliseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlow = time / 1000
				case netflow.IPFIX_FIELD_flowEndMicroseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlow = time / 1000000
				case netflow.IPFIX_FIELD_flowEndNanoseconds:
					DecodeUNumber(v, &time)
					flowMessage.TimeFlow = time / 1000000000
				}
			}
		}

	}

	if flowMessage.TimeFlow < flowMessage.TimeRecvd {
		return flowMessage
	} else {
		NetFlowErrors.With(
			prometheus.Labels{
				"router":  routerStr,
				"version": strconv.Itoa(int(version)),
				"error":   "garbage",
			}).
			Inc()
		return nil
		// Silently discard bad packet
	}
}

/*func ConvertNetFlowDataSet(router net.IP, version uint16, seqnum uint32, sampling uint64, baseTime uint32, uptime uint32, record []netflow.DataField) *flowmessage.FlowMessage {
    routerStr := router.String()
    flowMessage := &flowmessage.FlowMessage{}

    flowMessage.SamplingRate = sampling

    var proto uint8
    NetFlowPopulate(record, 4, &proto)
    flowMessage.Proto = uint32(proto)

    var srcPort uint16
    var dstPort uint16

    NetFlowPopulate(record, 7, &srcPort)
    NetFlowPopulate(record, 11, &dstPort)
    flowMessage.SrcPort = uint32(srcPort)
    flowMessage.DstPort = uint32(dstPort)

    NetFlowPopulate(record, 16, &(flowMessage.SrcAS))
    NetFlowPopulate(record, 17, &(flowMessage.DstAS))
    NetFlowPopulate(record, 10, &(flowMessage.SrcIf))
    NetFlowPopulate(record, 14, &(flowMessage.DstIf))
    NetFlowPopulate(record, 89, &(flowMessage.ForwardingStatus))

    var ttl uint8
    NetFlowPopulate(record, 52, &ttl)
    flowMessage.IPTTL = uint32(ttl)
    var tos uint8
    NetFlowPopulate(record, 5, &tos)
    flowMessage.IPTos = uint32(tos)
    var tcpFlags uint8
    NetFlowPopulate(record, 6, &tcpFlags)
    flowMessage.TCPFlags = uint32(tcpFlags)

    ipSrc := net.IP{}
    ipDst := net.IP{}
    ipNh := net.IP{}
    isv4 := NetFlowPopulate(record, 8, &(ipSrc))
    if(isv4) {
        NetFlowPopulate(record, 12, &(ipDst))
        NetFlowPopulate(record, 15, &(ipNh))
        NetFlowPopulate(record, 18, &(ipNh))

        flowMessage.IPversion = flowmessage.FlowMessage_IPv4
    } else {
        NetFlowPopulate(record, 27, &(ipSrc))
        NetFlowPopulate(record, 28, &(ipDst))
        NetFlowPopulate(record, 62, &(ipNh))
        NetFlowPopulate(record, 63, &(ipNh))

        flowMessage.IPversion = flowmessage.FlowMessage_IPv6
    }
    flowMessage.SrcIP = ipSrc
    flowMessage.DstIP = ipDst
    flowMessage.NextHop = ipNh
    flowMessage.RouterAddr = router

    var srcmask byte
    var dstmask byte
    NetFlowPopulate(record, 9, &srcmask)
    NetFlowPopulate(record, 13, &dstmask)
    flowMessage.SrcNet = uint32(srcmask)
    flowMessage.DstNet = uint32(dstmask)

    recvd := uint64(time.Now().Unix())
    flowMessage.TimeRecvd = recvd
    var flowTime uint64
    var bytes uint64
    var packets uint64

    if(version == 9) {
        var bytes32 uint32
        var packets32 uint32
        NetFlowPopulate(record, 1, &bytes32)
        NetFlowPopulate(record, 2, &packets32)
        bytes = uint64(bytes32)
        packets = uint64(packets32)

        flowMessage.Type = flowmessage.FlowMessage_NFV9
        flowMessage.SequenceNum = seqnum

        var timeLastSwitched uint32;
        NetFlowPopulate(record, 21, &timeLastSwitched)
        NetFlowPopulate(record, 21, &timeLastSwitched)
        timeDiff := (uptime - timeLastSwitched)/1000
        flowTime = uint64(baseTime - timeDiff)

    } else if(version == 10) {
        NetFlowPopulate(record, 1, &bytes)
        NetFlowPopulate(record, 2, &packets)

        flowMessage.Type = flowmessage.FlowMessage_IPFIX
        flowMessage.SequenceNum = seqnum

        var time uint64;
        NetFlowPopulate(record, 153, &time)
        flowTime = uint64(time/1000)
    }
    flowMessage.Bytes = bytes
    flowMessage.Packets = packets

    if(flowTime < recvd) {
        flowMessage.TimeFlow = flowTime
        return flowMessage
    } else {
        NetFlowErrors.With(
        prometheus.Labels{
            "router": routerStr,
            "version": strconv.Itoa(int(version)),
            "error": "garbage",
            }).
        Inc()
        return nil
        //flowMessage.TimeFlow = recvd
        // Silently discard bad packet
    }
}*/

func SearchNetFlowDataSets(router net.IP, version uint16, seqnum uint32, sampling uint64, baseTime uint32, uptime uint32, dataFlowSet []netflow.DataFlowSet) []flowmessage.FlowMessage {
	flowMessageSet := make([]flowmessage.FlowMessage, 0)
	for _, dataFlowSetItem := range dataFlowSet {
		for _, record := range dataFlowSetItem.Records {
			fmsg := ConvertNetFlowDataSet(router, version, seqnum, sampling, baseTime, uptime, record.Values)
			if fmsg != nil {
				flowMessageSet = append(flowMessageSet, *fmsg)
			}
		}
	}
	return flowMessageSet
}

func GetSamplingRate(key string, obsDomainId uint32, optionsDataFlowSet []netflow.OptionsDataFlowSet, samplingRateLock *sync.RWMutex, samplingRateMap SamplingRateMap) uint64 {

	for _, optionsDataFlowSetItem := range optionsDataFlowSet {
		for _, record := range optionsDataFlowSetItem.Records {
			var samplingRate uint32
			NetFlowPopulate(record.OptionsValues, 34, &samplingRate)
			samplingRateLock.Lock()
			samplingRateMap[key][obsDomainId] = uint64(samplingRate)
			samplingRateLock.Unlock()
		}
	}

	samplingRateLock.RLock()
	samplingRate := samplingRateMap[key][obsDomainId]
	samplingRateLock.RUnlock()

	return samplingRate
}

func GetNetFlowTemplatesSets(version uint16, packet interface{}) []netflow.TemplateFlowSet {
	templatesFlowSet := make([]netflow.TemplateFlowSet, 0)
	if version == 9 {
		packetNFv9 := packet.(netflow.NFv9Packet)
		for _, flowSet := range packetNFv9.FlowSets {
			switch flowSet.(type) {
			case netflow.TemplateFlowSet:
				templatesFlowSet = append(templatesFlowSet, flowSet.(netflow.TemplateFlowSet))
			}
		}
	} else if version == 10 {
		packetIPFIX := packet.(netflow.IPFIXPacket)
		for _, flowSet := range packetIPFIX.FlowSets {
			switch flowSet.(type) {
			case netflow.TemplateFlowSet:
				templatesFlowSet = append(templatesFlowSet, flowSet.(netflow.TemplateFlowSet))
			}
		}
	}
	return templatesFlowSet
}

func ProcessTemplates(router string, obsDomainId uint32, version uint16, templatesFlowSet []netflow.TemplateFlowSet, templateMap TemplateMap, templateMapLock *sync.RWMutex) {
	for _, flowSet := range templatesFlowSet {
		for _, record := range flowSet.Records {
			CountTemplate(router, obsDomainId, true, version, record.TemplateId, templateMap, templateMapLock)
		}
	}
}

func GetNetFlowOptionsTemplatesSets(version uint16, packet interface{}) []interface{} {
	optionsTemplatesFlowSet := make([]interface{}, 0)
	if version == 9 {
		packetNFv9 := packet.(netflow.NFv9Packet)
		for _, flowSet := range packetNFv9.FlowSets {
			switch flowSet.(type) {
			case netflow.NFv9OptionsTemplateFlowSet:
				optionsTemplatesFlowSet = append(optionsTemplatesFlowSet, flowSet.(netflow.NFv9OptionsTemplateFlowSet))
			}
		}
	} else if version == 10 {
		packetIPFIX := packet.(netflow.IPFIXPacket)
		for _, flowSet := range packetIPFIX.FlowSets {
			switch flowSet.(type) {
			case netflow.IPFIXOptionsTemplateFlowSet:
				optionsTemplatesFlowSet = append(optionsTemplatesFlowSet, flowSet.(netflow.IPFIXOptionsTemplateFlowSet))
			}
		}
	}
	return optionsTemplatesFlowSet
}

func CountTemplate(router string, obsDomainId uint32, notOptions bool, version uint16, id uint16, templateMap TemplateMap, templateMapLock *sync.RWMutex) {
	templateMapLock.RLock()
	_, ok := templateMap[router][obsDomainId][id]
	templateMapLock.RUnlock()
	if ok == false {
		templateMapLock.Lock()
		_, oksrc := templateMap[router]
		if oksrc == false {
			templateMap[router] = make(map[uint32]map[uint16]bool)
		}
		_, okobs := templateMap[router][obsDomainId]
		if okobs == false {
			templateMap[router][obsDomainId] = make(map[uint16]bool)
		}

		typeStr := "template"
		if notOptions == false {
			typeStr = "options_template"
		}

		templateMap[router][obsDomainId][id] = false
		templateMapLock.Unlock()
		NetFlowTemplatesStats.With(
			prometheus.Labels{
				"router":        router,
				"version":       strconv.Itoa(int(version)),
				"obs_domain_id": strconv.Itoa(int(obsDomainId)),
				"type":          typeStr,
			}).
			Inc()
	}
}

func ProcessOptionsTemplates(router string, obsDomainId uint32, version uint16, templatesFlowSet []interface{}, templateMap TemplateMap, templateMapLock *sync.RWMutex) {
	for _, flowSet := range templatesFlowSet {
		if version == 9 {
			for _, record := range flowSet.(netflow.NFv9OptionsTemplateFlowSet).Records {
				CountTemplate(router, obsDomainId, false, version, record.TemplateId, templateMap, templateMapLock)
			}
		} else if version == 10 {
			for _, record := range flowSet.(netflow.IPFIXOptionsTemplateFlowSet).Records {
				CountTemplate(router, obsDomainId, false, version, record.TemplateId, templateMap, templateMapLock)
			}
		}
	}
}

func GetNetFlowOptionsDataSets(version uint16, packet interface{}) []netflow.OptionsDataFlowSet {
	optionsDataFlowSet := make([]netflow.OptionsDataFlowSet, 0)
	if version == 9 {
		packetNFv9 := packet.(netflow.NFv9Packet)
		for _, flowSet := range packetNFv9.FlowSets {
			switch flowSet.(type) {
			case netflow.OptionsDataFlowSet:
				optionsDataFlowSet = append(optionsDataFlowSet, flowSet.(netflow.OptionsDataFlowSet))
			}
		}
	} else if version == 10 {
		packetIPFIX := packet.(netflow.IPFIXPacket)
		for _, flowSet := range packetIPFIX.FlowSets {
			switch flowSet.(type) {
			case netflow.OptionsDataFlowSet:
				optionsDataFlowSet = append(optionsDataFlowSet, flowSet.(netflow.OptionsDataFlowSet))
			}
		}
	}
	return optionsDataFlowSet
}

func GetNetFlowDataFlowSets(version uint16, packet interface{}) []netflow.DataFlowSet {
	dataFlowSet := make([]netflow.DataFlowSet, 0)
	if version == 9 {
		packetNFv9 := packet.(netflow.NFv9Packet)
		for _, flowSet := range packetNFv9.FlowSets {
			switch flowSet.(type) {
			case netflow.DataFlowSet:
				dataFlowSet = append(dataFlowSet, flowSet.(netflow.DataFlowSet))
			}
		}
	} else if version == 10 {
		packetIPFIX := packet.(netflow.IPFIXPacket)
		for _, flowSet := range packetIPFIX.FlowSets {
			switch flowSet.(type) {
			case netflow.DataFlowSet:
				dataFlowSet = append(dataFlowSet, flowSet.(netflow.DataFlowSet))
			}
		}
	}
	return dataFlowSet
}

func ProcessNetFlowError(msgDec interface{}, err error, args interface{}, conf interface{}) (bool, error) {
	msgDecoded := msgDec.(netflow.BaseMessageDecoded)
	packet := msgDecoded.Packet
	version := msgDecoded.Version
	seqnum := uint32(0)
	if version == 9 {
		seqnum = packet.(netflow.NFv9Packet).SequenceNumber
	} else if version == 10 {
		seqnum = packet.(netflow.IPFIXPacket).SequenceNumber
	}

	switch err := err.(type) {
	case *netflow.ErrorTemplateNotFound:
		log.WithFields(log.Fields{
			"version": version,
			"source":  msgDecoded.Src.String(),
			"seqnum":  seqnum,
			"error":   err,
		}).Debug("Template not found")

		NetFlowErrors.With(
			prometheus.Labels{
				"router":  msgDecoded.Src.String(),
				"version": strconv.Itoa(int(version)),
				"error":   "template_not_found",
			}).
			Add(1)
	default:
		log.WithFields(log.Fields{
			"version": version,
			"source":  msgDecoded.Src.String(),
			"seqnum":  seqnum,
			"error":   err,
		}).Error("Error processing")

		NetFlowErrors.With(
			prometheus.Labels{
				"router":  msgDecoded.Src.String(),
				"version": strconv.Itoa(int(version)),
				"error":   "undefined",
			}).
			Add(1)
	}

	return true, nil
}

func MetricTypeNetFlow(router string, version uint16, packet interface{}) {
	countMap := make(map[string]int)
	countRecordsMap := make(map[string]int)
	if version == 9 {
		packetNFv9 := packet.(netflow.NFv9Packet)
		for _, flowSet := range packetNFv9.FlowSets {
			switch flowSet := flowSet.(type) {
			case netflow.TemplateFlowSet:
				countMap["TemplateFlowSet"]++
				countRecordsMap["TemplateFlowSet"] += len(flowSet.Records)
			case netflow.DataFlowSet:
				countMap["DataFlowSet"]++
				countRecordsMap["DataFlowSet"] += len(flowSet.Records)
			case netflow.NFv9OptionsTemplateFlowSet:
				countMap["OptionsTemplateFlowSet"]++
				countRecordsMap["OptionsTemplateFlowSet"] += len(flowSet.Records)
			case netflow.OptionsDataFlowSet:
				countMap["OptionsDataFlowSet"]++
				countRecordsMap["OptionsDataFlowSet"] += len(flowSet.Records)
			}
		}
	} else if version == 10 {
		packetIPFIX := packet.(netflow.IPFIXPacket)
		for _, flowSet := range packetIPFIX.FlowSets {
			switch flowSet := flowSet.(type) {
			case netflow.TemplateFlowSet:
				countMap["TemplateFlowSet"]++
				countRecordsMap["TemplateFlowSet"] += len(flowSet.Records)
			case netflow.DataFlowSet:
				countMap["DataFlowSet"]++
				countRecordsMap["DataFlowSet"] += len(flowSet.Records)
			case netflow.IPFIXOptionsTemplateFlowSet:
				countMap["OptionsTemplateFlowSet"]++
				countRecordsMap["OptionsTemplateFlowSet"] += len(flowSet.Records)
			case netflow.OptionsDataFlowSet:
				countMap["OptionsDataFlowSet"]++
				countRecordsMap["OptionsDataFlowSet"] += len(flowSet.Records)
			}
		}
	}

	for keyType := range countMap {
		NetFlowSetStatsSum.With(
			prometheus.Labels{
				"router":  router,
				"version": strconv.Itoa(int(version)),
				"type":    keyType,
			}).
			Add(float64(countMap[keyType]))

		NetFlowSetRecordsStatsSum.With(
			prometheus.Labels{
				"router":  router,
				"version": strconv.Itoa(int(version)),
				"type":    keyType,
			}).
			Add(float64(countRecordsMap[keyType]))
	}

}

func ProcessMessageNetFlow(msgDec interface{}, args interface{}, conf interface{}) (bool, error) {
	msgDecoded := msgDec.(netflow.BaseMessageDecoded)
	packet := msgDecoded.Packet

	version := msgDecoded.Version
	seqnum := uint32(0)
	router := msgDecoded.Src.String() + ":" + strconv.Itoa(msgDecoded.Port)
	var baseTime uint32
	var uptime uint32
	var obsDomainId uint32
	if version == 9 {
		seqnum = packet.(netflow.NFv9Packet).SequenceNumber
		baseTime = packet.(netflow.NFv9Packet).UnixSeconds
		uptime = packet.(netflow.NFv9Packet).SystemUptime
		obsDomainId = packet.(netflow.NFv9Packet).SourceId
	} else if version == 10 {
		seqnum = packet.(netflow.IPFIXPacket).SequenceNumber
		baseTime = packet.(netflow.IPFIXPacket).ExportTime
		obsDomainId = packet.(netflow.IPFIXPacket).ObservationDomainId
	}

	if version == 9 || version == 10 {
		dataFlowSet := GetNetFlowDataFlowSets(msgDecoded.Version, packet)

		args, ok := args.(ProcessArguments)
		if ok {
			var samplingRate uint64
			routerKey := router
			if args.SamplingRateFixed == -1 {
				optionsDataFlowSet := GetNetFlowOptionsDataSets(msgDecoded.Version, packet)
				if args.UniqueTemplates {
					routerKey = "unique"
				}
				samplingRate = GetSamplingRate(routerKey, obsDomainId, optionsDataFlowSet, args.SamplingRateLock, args.SamplingRateMap)
			} else {
				samplingRate = uint64(args.SamplingRateFixed)
			}
			templatesFlowSet := GetNetFlowTemplatesSets(version, packet)
			ProcessTemplates(routerKey, obsDomainId, version, templatesFlowSet, args.TemplateMap, args.TemplateMapLock)
			optionsTemplatesFlowSet := GetNetFlowOptionsTemplatesSets(version, packet)
			ProcessOptionsTemplates(routerKey, obsDomainId, version, optionsTemplatesFlowSet, args.TemplateMap, args.TemplateMapLock)

			flowMessageSet := SearchNetFlowDataSets(msgDecoded.Src, msgDecoded.Version, seqnum, samplingRate, baseTime, uptime, dataFlowSet)

			MetricTypeNetFlow(router, msgDecoded.Version, packet)
			NetFlowStats.With(
				prometheus.Labels{
					"router":  router,
					"version": strconv.Itoa(int(version)),
				}).
				Inc()

			log.WithFields(log.Fields{
				"type":               "NetFlow/IPFIX",
				"version":            version,
				"source":             router,
				"seqnum":             seqnum,
				"samplingRate":       strconv.Itoa(int(samplingRate)),
				"count_flowmessages": len(flowMessageSet),
			}).Debug("Message processed")

			for _, flowMessage := range flowMessageSet {
				if args.KafkaState != nil {
					args.KafkaState.SendKafkaFlowMessage(flowMessage)
				}

				timeDiff := flowMessage.TimeRecvd - flowMessage.TimeFlow

				NetFlowTimeStatsSum.With(
					prometheus.Labels{
						"router":  router,
						"version": strconv.Itoa(int(version)),
					}).
					Observe(float64(timeDiff))
			}
		}
	} else {
		NetFlowErrors.With(
			prometheus.Labels{
				"router":  router,
				"version": "unknown",
				"error":   "netflow_version",
			}).
			Inc()

		return false, errors.New(fmt.Sprintf("Bad NetFlow version: %v\n", version))
	}

	return true, nil
}
