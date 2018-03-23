package sflow

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cloudflare/goflow/decoders"
	"github.com/cloudflare/goflow/decoders/utils"
	"net"
)

const (
	FORMAT_EXT_SWITCH  = 1001
	FORMAT_EXT_ROUTER  = 1002
	FORMAT_EXT_GATEWAY = 1003
	FORMAT_RAW_PKT     = 1
	FORMAT_ETH         = 2
	FORMAT_IPV4        = 3
	FORMAT_IPV6        = 4
)

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte
}

type BaseMessageDecoded struct {
	Version uint32
	Src     net.IP
	Port    int
	Packet  decoder.MessageDecoded
}

type DecoderConfig struct {
}

func CreateConfig() DecoderConfig {
	config := DecoderConfig{}
	return config
}

func DecodePacket(msg decoder.Message, config decoder.DecoderConfig) (decoder.MessageDecoded, error) {
	baseMsg := msg.(BaseMessage)
	payload := bytes.NewBuffer(baseMsg.Payload)

	version, msgDecoded, err := DecodeMessage(payload, config)

	baseMsgDecoded := BaseMessageDecoded{
		Version: version,
		Src:     baseMsg.Src,
		Port:    baseMsg.Port,
		Packet:  msgDecoded,
	}

	return baseMsgDecoded, err
}

func DecodeCounterRecord(header *RecordHeader, payload *bytes.Buffer) (CounterRecord, error) {
	counterRecord := CounterRecord{
		Header: *header,
	}
	switch (*header).DataFormat {
	case 1:
		ifCounters := IfCounters{}
		utils.BinaryDecoder(payload, &ifCounters)
		counterRecord.Data = ifCounters
	case 2:
		ethernetCounters := EthernetCounters{}
		utils.BinaryDecoder(payload, &ethernetCounters)
		counterRecord.Data = ethernetCounters
	default:
		return counterRecord, errors.New(fmt.Sprintf("Unknown data format %v.", (*header).DataFormat))
	}
	//fmt.Printf("%v\n", counterRecord)

	return counterRecord, nil
}

func DecodeIP(payload *bytes.Buffer) (uint32, []byte, error) {
	var ipVersion uint32
	utils.BinaryDecoder(payload, &ipVersion)
	var ip []byte
	if ipVersion == 1 {
		ip = make([]byte, 4)
	} else if ipVersion == 2 {
		ip = make([]byte, 16)
	} else {
		return ipVersion, ip, errors.New(fmt.Sprintf("Unknown Next Hop IP version %v.", ipVersion))
	}
	if payload.Len() >= len(ip) {
		utils.BinaryDecoder(payload, &ip)
	} else {
		return ipVersion, ip, errors.New(fmt.Sprintf("Not enough data: %v, needs %v.", payload.Len(), len(ip)))
	}
	return ipVersion, ip, nil
}

func DecodeFlowRecord(header *RecordHeader, payload *bytes.Buffer) (FlowRecord, error) {
	flowRecord := FlowRecord{
		Header: *header,
	}
	switch (*header).DataFormat {
	case FORMAT_EXT_SWITCH:
		extendedSwitch := ExtendedSwitch{}
		utils.BinaryDecoder(payload, &extendedSwitch)
		flowRecord.Data = extendedSwitch
	case FORMAT_RAW_PKT:
		sampledHeader := SampledHeader{}
		utils.BinaryDecoder(payload, &(sampledHeader.Protocol), &(sampledHeader.FrameLength), &(sampledHeader.Stripped), &(sampledHeader.OriginalLength))
		sampledHeader.HeaderData = payload.Bytes()
		flowRecord.Data = sampledHeader
	case FORMAT_IPV4:
		sampledIPBase := SampledIP_Base{
			SrcIP: make([]byte, 4),
			DstIP: make([]byte, 4),
		}
		utils.BinaryDecoder(payload, &sampledIPBase)
		sampledIPv4 := SampledIPv4{
			Base: sampledIPBase,
		}
		utils.BinaryDecoder(payload, &(sampledIPv4.Tos))
		flowRecord.Data = sampledIPv4
	case FORMAT_IPV6:
		sampledIPBase := SampledIP_Base{
			SrcIP: make([]byte, 16),
			DstIP: make([]byte, 16),
		}
		utils.BinaryDecoder(payload, &sampledIPBase)
		sampledIPv6 := SampledIPv6{
			Base: sampledIPBase,
		}
		utils.BinaryDecoder(payload, &(sampledIPv6.Priority))
		flowRecord.Data = sampledIPv6
	case FORMAT_EXT_ROUTER:
		extendedRouter := ExtendedRouter{}

		ipVersion, ip, err := DecodeIP(payload)
		if err != nil {
			return flowRecord, err
		}
		extendedRouter.NextHopIPVersion = ipVersion
		extendedRouter.NextHop = ip
		utils.BinaryDecoder(payload, &(extendedRouter.SrcMaskLen), &(extendedRouter.DstMaskLen))
		flowRecord.Data = extendedRouter
	case FORMAT_EXT_GATEWAY:
		extendedGateway := ExtendedGateway{}
		ipVersion, ip, err := DecodeIP(payload)
		if err != nil {
			return flowRecord, err
		}
		extendedGateway.NextHopIPVersion = ipVersion
		extendedGateway.NextHop = ip
		utils.BinaryDecoder(payload, &(extendedGateway.AS), &(extendedGateway.SrcAS), &(extendedGateway.SrcPeerAS),
			&(extendedGateway.ASDestinations))
		asPath := make([]uint32, 0)
		if extendedGateway.ASDestinations != 0 {
			utils.BinaryDecoder(payload, &(extendedGateway.ASPathType), &(extendedGateway.ASPathLength))
			if int(extendedGateway.ASPathLength) > payload.Len()-4 {
				return flowRecord, errors.New(fmt.Sprintf("Invalid AS path length.", extendedGateway.ASPathLength))
			}
			asPath = make([]uint32, extendedGateway.ASPathLength)
			if len(asPath) > 0 {
				utils.BinaryDecoder(payload, asPath)
			}
		}
		extendedGateway.ASPath = asPath

		utils.BinaryDecoder(payload, &(extendedGateway.CommunitiesLength))
		if int(extendedGateway.CommunitiesLength) > payload.Len()-4 {
			return flowRecord, errors.New(fmt.Sprintf("Invalid Communities length.", extendedGateway.ASPathLength))
		}
		communities := make([]uint32, extendedGateway.CommunitiesLength)
		if len(communities) > 0 {
			utils.BinaryDecoder(payload, communities)
		}
		utils.BinaryDecoder(payload, &(extendedGateway.LocalPref))
		extendedGateway.Communities = communities

		flowRecord.Data = extendedGateway
	default:
		return flowRecord, errors.New(fmt.Sprintf("Unknown data format %v.", (*header).DataFormat))
	}
	/*if((*header).DataFormat == 1002) {
	    fmt.Printf("%v\n", flowRecord)
	}*/
	return flowRecord, nil
}

func DecodeSample(header *SampleHeader, payload *bytes.Buffer, config decoder.DecoderConfig) (interface{}, error) {
	format := (*header).Format
	var sample interface{}

	utils.BinaryDecoder(payload, &((*header).SampleSequenceNumber))
	if format == FORMAT_RAW_PKT || format == FORMAT_ETH {
		var sourceId uint32
		utils.BinaryDecoder(payload, &sourceId)

		(*header).SourceIdType = sourceId >> 24
		(*header).SourceIdValue = sourceId & 0x00ffffff
	} else if format == FORMAT_IPV4 || format == FORMAT_IPV6 {
		utils.BinaryDecoder(payload, &((*header).SourceIdType), &((*header).SourceIdValue))
	} else {
		return nil, errors.New(fmt.Sprintf("Unknown format %v.", format))
	}

	var recordsCount uint32
	var flowSample FlowSample
	var counterSample CounterSample
	var expandedFlowSample ExpandedFlowSample
	if format == FORMAT_RAW_PKT {
		flowSample = FlowSample{
			Header: *header,
		}
		utils.BinaryDecoder(payload, &(flowSample.SamplingRate), &(flowSample.SamplePool),
			&(flowSample.Drops), &(flowSample.Input), &(flowSample.Output), &(flowSample.FlowRecordsCount))
		recordsCount = flowSample.FlowRecordsCount
		flowSample.Records = make([]FlowRecord, recordsCount)
		sample = flowSample
	} else if format == FORMAT_ETH || format == FORMAT_IPV6 {
		utils.BinaryDecoder(payload, &recordsCount)
		counterSample = CounterSample{
			Header:              *header,
			CounterRecordsCount: recordsCount,
		}
		counterSample.Records = make([]CounterRecord, recordsCount)
		sample = counterSample
	} else if format == FORMAT_IPV4 {
		expandedFlowSample = ExpandedFlowSample{
			Header: *header,
		}
		utils.BinaryDecoder(payload, &(expandedFlowSample.SamplingRate), &(expandedFlowSample.SamplePool),
			&(expandedFlowSample.Drops), &(expandedFlowSample.InputIfFormat), &(expandedFlowSample.InputIfValue),
			&(expandedFlowSample.OutputIfFormat), &(expandedFlowSample.OutputIfValue), &(expandedFlowSample.FlowRecordsCount))
		recordsCount = expandedFlowSample.FlowRecordsCount
		expandedFlowSample.Records = make([]FlowRecord, recordsCount)
		sample = expandedFlowSample
	}
	for i := 0; i < int(recordsCount) && payload.Len() >= 8; i++ {
		recordHeader := RecordHeader{}
		utils.BinaryDecoder(payload, &(recordHeader.DataFormat), &(recordHeader.Length))
		if int(recordHeader.Length) > payload.Len() {
			break
		}
		recordReader := bytes.NewBuffer(payload.Next(int(recordHeader.Length)))
		if format == FORMAT_RAW_PKT || format == FORMAT_IPV4 {
			record, err := DecodeFlowRecord(&recordHeader, recordReader)
			if err != nil {
				continue
			}
			if format == FORMAT_RAW_PKT {
				flowSample.Records[i] = record
			} else if format == FORMAT_IPV4 {
				expandedFlowSample.Records[i] = record
			}
		} else if format == FORMAT_ETH || format == FORMAT_IPV6 {
			record, err := DecodeCounterRecord(&recordHeader, recordReader)
			if err != nil {
				continue
			}
			counterSample.Records[i] = record
		}
	}
	//fmt.Printf("%v\n", sample)
	return sample, nil
}

func DecodeMessage(payload *bytes.Buffer, config decoder.DecoderConfig) (uint32, decoder.MessageDecoded, error) {
	var version uint32
	utils.BinaryDecoder(payload, &version)
	packetV5 := Packet{}
	if version == 5 {
		packetV5.Version = version
		utils.BinaryDecoder(payload, &(packetV5.IPVersion))
		var ip []byte
		if packetV5.IPVersion == 1 {
			ip = make([]byte, 4)
			utils.BinaryDecoder(payload, ip)
		} else if packetV5.IPVersion == 2 {
			ip = make([]byte, 16)
			utils.BinaryDecoder(payload, ip)
		} else {
			return version, nil, errors.New(fmt.Sprintf("Unknown IP version %v.", packetV5.IPVersion))
		}

		packetV5.AgentIP = ip
		utils.BinaryDecoder(payload, &(packetV5.SubAgentId), &(packetV5.SequenceNumber), &(packetV5.Uptime), &(packetV5.SamplesCount))
		packetV5.Samples = make([]interface{}, int(packetV5.SamplesCount))
		for i := 0; i < int(packetV5.SamplesCount) && payload.Len() >= 8; i++ {
			header := SampleHeader{}
			utils.BinaryDecoder(payload, &(header.Format), &(header.Length))
			if int(header.Length) > payload.Len() {
				break
			}
			sampleReader := bytes.NewBuffer(payload.Next(int(header.Length)))

			sample, err := DecodeSample(&header, sampleReader, config)
			if err != nil {
				// log
				continue
			} else {
				packetV5.Samples[i] = sample
			}
		}

		//fmt.Printf("%v\n", packetV5)
		return version, packetV5, nil
	} else {
		return version, nil, errors.New(fmt.Sprintf("Unknown version %v.", version))
	}
	return version, nil, nil
}

func CreateProcessor(numWorkers int, decoderConfig DecoderConfig, doneCallback decoder.DoneCallback, callbackArgs decoder.CallbackArgs, errorCallback decoder.ErrorCallback) decoder.Processor {

	decoderParams := decoder.DecoderParams{
		DecoderFunc:   DecodePacket,
		DecoderConfig: decoderConfig,
		DoneCallback:  doneCallback,
		CallbackArgs:  callbackArgs,
		ErrorCallback: errorCallback,
	}
	processor := decoder.CreateProcessor(numWorkers, decoderParams, "sFlow")

	return processor
}
