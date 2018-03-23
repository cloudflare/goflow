package producer

import (
	"encoding/binary"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/cloudflare/goflow/decoders/sflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/prometheus/client_golang/prometheus"
	"net"
	"strconv"
	"time"
)

var (
	SFlowStats = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_sf_count",
			Help: "sFlows processed.",
		},
		[]string{"router", "agent", "version"},
	)
	SFlowErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_sf_errors_count",
			Help: "sFlows processed errors.",
		},
		[]string{"router", "version", "error"},
	)
	SFlowSampleStatsSum = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_sf_samples_sum",
			Help: "SFlows samples sum.",
		},
		[]string{"router", "agent", "version", "type"}, // counter, flow, expanded...
	)
	SFlowSampleRecordsStatsSum = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_process_sf_samples_records_sum",
			Help: "SFlows samples sum of records.",
		},
		[]string{"router", "agent", "version", "type"}, // data-template, data, opts...
	)
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

		srcMac = binary.BigEndian.Uint64(append([]byte{0, 0}, data[0:6]...))
		dstMac = binary.BigEndian.Uint64(append([]byte{0, 0}, data[6:12]...))
		(*flowMessage).SrcMac = srcMac
		(*flowMessage).DstMac = dstMac

		if etherType[0] == 0x81 && etherType[1] == 0x0 { // VLAN 802.1Q
			(*flowMessage).VlanId = uint32(binary.BigEndian.Uint16(data[14:16]))
			offset += 4
			etherType = data[16:18]
		}

		(*flowMessage).Etype = uint32(binary.BigEndian.Uint16(etherType[0:2]))

		if etherType[0] == 0x8 && etherType[1] == 0x0 { // IPv4
			(*flowMessage).IPversion = flowmessage.FlowMessage_IPv4

			if len(data) >= offset+36 {
				nextHeader = data[offset+9]
				srcIP = data[offset+12 : offset+16]
				dstIP = data[offset+16 : offset+20]
				dataTransport = data[offset+20 : len(data)]
				tos = data[offset+1]
				ttl = data[offset+8]
			}
		} else if etherType[0] == 0x86 && etherType[1] == 0xdd { // IPv6
			(*flowMessage).IPversion = flowmessage.FlowMessage_IPv6
			if len(data) >= offset+40 {
				nextHeader = data[offset+6]
				srcIP = data[offset+8 : offset+24]
				dstIP = data[offset+24 : offset+40]
				dataTransport = data[offset+40 : len(data)]

				tostmp := uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
				tos = uint8(tostmp & 0x0ff0 >> 4)
				ttl = data[offset+7]
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

		(*flowMessage).SrcIP = srcIP
		(*flowMessage).DstIP = dstIP
		(*flowMessage).Proto = uint32(nextHeader)
		(*flowMessage).IPTos = uint32(tos)
		(*flowMessage).IPTTL = uint32(ttl)
		(*flowMessage).TCPFlags = uint32(tcpflags)

		//fmt.Printf("TEst %v:%v %v:%v \n", srcIP.String(), (*flowMessage).SrcPort, dstIP.String(), (*flowMessage).DstPort)
	}
	return nil
}

func SearchSFlowSamples(router net.IP, agent net.IP, version uint32, seqnum uint32, samples []interface{}) []flowmessage.FlowMessage {
	flowMessageSet := make([]flowmessage.FlowMessage, 0)
	//routerStr := router.String()
	//agentStr  := agent.String()

	for _, flowSample := range samples {
		var records []sflow.FlowRecord

		flowMessage := flowmessage.FlowMessage{}
		flowMessage.Type = flowmessage.FlowMessage_SFLOW

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

		flowMessage.SequenceNum = seqnum
		recvd := uint64(time.Now().Unix())
		flowMessage.TimeRecvd = recvd
		flowMessage.TimeFlow = recvd

		ipNh := net.IP{}
		ipSrc := net.IP{}
		ipDst := net.IP{}
		flowMessage.Packets = 1
		flowMessage.RouterAddr = agent
		for _, record := range records {
			switch recordData := record.Data.(type) {
			case sflow.SampledHeader:
				flowMessage.Bytes = uint64(recordData.FrameLength)
				ParseSampledHeader(&flowMessage, &recordData)
			case sflow.SampledIPv4:
				ipSrc = recordData.Base.SrcIP
				ipDst = recordData.Base.DstIP
				flowMessage.SrcIP = ipSrc
				flowMessage.DstIP = ipDst
				flowMessage.IPversion = flowmessage.FlowMessage_IPv4
				flowMessage.Bytes = uint64(recordData.Base.Length)
				flowMessage.Proto = recordData.Base.Protocol
				flowMessage.SrcPort = recordData.Base.SrcPort
				flowMessage.DstPort = recordData.Base.DstPort
				flowMessage.IPTos = recordData.Tos
				flowMessage.Etype = 0x800
			case sflow.SampledIPv6:
				ipSrc = recordData.Base.SrcIP
				ipDst = recordData.Base.DstIP
				flowMessage.IPversion = flowmessage.FlowMessage_IPv6
				flowMessage.SrcIP = ipSrc
				flowMessage.DstIP = ipDst
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
			}
		}
		flowMessageSet = append(flowMessageSet, flowMessage)
		//fmt.Printf("%v\n", flowMessage.String())
	}
	return flowMessageSet
}

func MetricTypeSFlow(router string, agent string, version uint32, packet sflow.Packet) {
	countMap := make(map[string]int)
	countRecordsMap := make(map[string]int)
	if version == 5 {
		for _, flowSample := range packet.Samples {
			switch flowSample := flowSample.(type) {
			case sflow.FlowSample:
				countMap["FlowSample"]++
				countRecordsMap["FlowSample"] += len(flowSample.Records)
			case sflow.CounterSample:
				name := "CounterSample"
				if flowSample.Header.Format == 4 {
					name = "Expanded" + name
				}
				countMap[name]++
				countRecordsMap[name] += len(flowSample.Records)
			case sflow.ExpandedFlowSample:
				countMap["ExpandedFlowSample"]++
				countRecordsMap["ExpandedFlowSample"] += len(flowSample.Records)
			}
		}
	}

	for keyType := range countMap {
		SFlowSampleStatsSum.With(
			prometheus.Labels{
				"router":  router,
				"agent":   agent,
				"version": strconv.Itoa(int(version)),
				"type":    keyType,
			}).
			Add(float64(countMap[keyType]))

		SFlowSampleRecordsStatsSum.With(
			prometheus.Labels{
				"router":  router,
				"agent":   agent,
				"version": strconv.Itoa(int(version)),
				"type":    keyType,
			}).
			Add(float64(countRecordsMap[keyType]))
	}
}

func ProcessSFlowError(msgDec interface{}, err error, args interface{}, conf interface{}) (bool, error) {
	return true, nil
}

func ProcessMessageSFlow(msgDec interface{}, args interface{}, conf interface{}) (bool, error) {
	msgDecoded := msgDec.(sflow.BaseMessageDecoded)
	packet := msgDecoded.Packet

	version := msgDecoded.Version
	router := msgDecoded.Src.String() + ":" + strconv.Itoa(msgDecoded.Port)
	if version == 5 {
		//fmt.Printf("%v %v %v\n", packet, router)
		packetV5, ok := packet.(sflow.Packet)
		args, ok2 := args.(ProcessArguments)
		if ok && ok2 {
			seqnum := packetV5.SequenceNumber
			var agent net.IP
			agent = packetV5.AgentIP

			flowSamples := GetSFlowFlowSamples(&packetV5)
			flowMessageSet := SearchSFlowSamples(msgDecoded.Src, agent, version, seqnum, flowSamples)

			MetricTypeSFlow(router, agent.String(), version, packetV5)
			SFlowStats.With(
				prometheus.Labels{
					"router":  router,
					"agent":   agent.String(),
					"version": strconv.Itoa(int(version)),
				}).
				Inc()

			log.WithFields(log.Fields{
				"type":               "sflow",
				"version":            version,
				"source":             router,
				"seqnum":             seqnum,
				"count_flowmessages": len(flowMessageSet),
			}).Debug("Message processed")

			for _, flowMessage := range flowMessageSet {
				if args.KafkaState != nil {
					args.KafkaState.SendKafkaFlowMessage(flowMessage)
				}
			}
		}

	} else {
		SFlowErrors.With(
			prometheus.Labels{
				"router":  router,
				"version": "unknown",
				"error":   "sflow_version",
			}).
			Inc()

		return false, errors.New(fmt.Sprintf("Bad SFlow version: %v\n", version))
	}

	return true, nil
}
