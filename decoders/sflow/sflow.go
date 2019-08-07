package sflow

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/cloudflare/goflow/decoders/utils"
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

type ErrorDecodingSFlow struct {
	msg string
}

func NewErrorDecodingSFlow(msg string) *ErrorDecodingSFlow {
	return &ErrorDecodingSFlow{
		msg: msg,
	}
}

func (e *ErrorDecodingSFlow) Error() string {
	return fmt.Sprintf("Error decoding sFlow: %v", e.msg)
}

type ErrorDataFormat struct {
	dataformat uint32
}

func NewErrorDataFormat(dataformat uint32) *ErrorDataFormat {
	return &ErrorDataFormat{
		dataformat: dataformat,
	}
}

func (e *ErrorDataFormat) Error() string {
	return fmt.Sprintf("Unknown data format %v", e.dataformat)
}

type ErrorIPVersion struct {
	version uint32
}

func NewErrorIPVersion(version uint32) *ErrorIPVersion {
	return &ErrorIPVersion{
		version: version,
	}
}

func (e *ErrorIPVersion) Error() string {
	return fmt.Sprintf("Unknown IP version: %v", e.version)
}

type ErrorVersion struct {
	version uint32
}

func NewErrorVersion(version uint32) *ErrorVersion {
	return &ErrorVersion{
		version: version,
	}
}

func (e *ErrorVersion) Error() string {
	return fmt.Sprintf("Unknown sFlow version %v (supported v5)", e.version)
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
		return counterRecord, NewErrorDataFormat((*header).DataFormat)
	}

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
		return ipVersion, ip, NewErrorIPVersion(ipVersion)
	}
	if payload.Len() >= len(ip) {
		utils.BinaryDecoder(payload, &ip)
	} else {
		return ipVersion, ip, NewErrorDecodingSFlow(fmt.Sprintf("Not enough data: %v, needs %v.", payload.Len(), len(ip)))
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
		err := utils.BinaryDecoder(payload, &extendedSwitch)
		if err != nil {
			return flowRecord, err
		}
		flowRecord.Data = extendedSwitch
	case FORMAT_RAW_PKT:
		sampledHeader := SampledHeader{}
		err := utils.BinaryDecoder(payload, &(sampledHeader.Protocol), &(sampledHeader.FrameLength), &(sampledHeader.Stripped), &(sampledHeader.OriginalLength))
		if err != nil {
			return flowRecord, err
		}
		sampledHeader.HeaderData = payload.Bytes()
		flowRecord.Data = sampledHeader
	case FORMAT_IPV4:
		sampledIPBase := SampledIP_Base{
			SrcIP: make([]byte, 4),
			DstIP: make([]byte, 4),
		}
		err := utils.BinaryDecoder(payload, &sampledIPBase)
		if err != nil {
			return flowRecord, err
		}
		sampledIPv4 := SampledIPv4{
			Base: sampledIPBase,
		}
		err = utils.BinaryDecoder(payload, &(sampledIPv4.Tos))
		if err != nil {
			return flowRecord, err
		}
		flowRecord.Data = sampledIPv4
	case FORMAT_IPV6:
		sampledIPBase := SampledIP_Base{
			SrcIP: make([]byte, 16),
			DstIP: make([]byte, 16),
		}
		err := utils.BinaryDecoder(payload, &sampledIPBase)
		if err != nil {
			return flowRecord, err
		}
		sampledIPv6 := SampledIPv6{
			Base: sampledIPBase,
		}
		err = utils.BinaryDecoder(payload, &(sampledIPv6.Priority))
		if err != nil {
			return flowRecord, err
		}
		flowRecord.Data = sampledIPv6
	case FORMAT_EXT_ROUTER:
		extendedRouter := ExtendedRouter{}

		ipVersion, ip, err := DecodeIP(payload)
		if err != nil {
			return flowRecord, err
		}
		extendedRouter.NextHopIPVersion = ipVersion
		extendedRouter.NextHop = ip
		err = utils.BinaryDecoder(payload, &(extendedRouter.SrcMaskLen), &(extendedRouter.DstMaskLen))
		if err != nil {
			return flowRecord, err
		}
		flowRecord.Data = extendedRouter
	case FORMAT_EXT_GATEWAY:
		extendedGateway := ExtendedGateway{}
		ipVersion, ip, err := DecodeIP(payload)
		if err != nil {
			return flowRecord, err
		}
		extendedGateway.NextHopIPVersion = ipVersion
		extendedGateway.NextHop = ip
		err = utils.BinaryDecoder(payload, &(extendedGateway.AS), &(extendedGateway.SrcAS), &(extendedGateway.SrcPeerAS),
			&(extendedGateway.ASDestinations))
		if err != nil {
			return flowRecord, err
		}
		asPath := make([]uint32, 0)
		if extendedGateway.ASDestinations != 0 {
			err := utils.BinaryDecoder(payload, &(extendedGateway.ASPathType), &(extendedGateway.ASPathLength))
			if err != nil {
				return flowRecord, err
			}
			if int(extendedGateway.ASPathLength) > payload.Len()-4 {
				return flowRecord, errors.New(fmt.Sprintf("Invalid AS path length: %v.", extendedGateway.ASPathLength))
			}
			asPath = make([]uint32, extendedGateway.ASPathLength)
			if len(asPath) > 0 {
				err = utils.BinaryDecoder(payload, asPath)
				if err != nil {
					return flowRecord, err
				}
			}
		}
		extendedGateway.ASPath = asPath

		err = utils.BinaryDecoder(payload, &(extendedGateway.CommunitiesLength))
		if err != nil {
			return flowRecord, err
		}
		if int(extendedGateway.CommunitiesLength) > payload.Len()-4 {
			return flowRecord, errors.New(fmt.Sprintf("Invalid Communities length: %v.", extendedGateway.ASPathLength))
		}
		communities := make([]uint32, extendedGateway.CommunitiesLength)
		if len(communities) > 0 {
			err = utils.BinaryDecoder(payload, communities)
			if err != nil {
				return flowRecord, err
			}
		}
		err = utils.BinaryDecoder(payload, &(extendedGateway.LocalPref))
		if err != nil {
			return flowRecord, err
		}
		extendedGateway.Communities = communities

		flowRecord.Data = extendedGateway
	default:
		return flowRecord, errors.New(fmt.Sprintf("Unknown data format %v.", (*header).DataFormat))
	}
	return flowRecord, nil
}

func DecodeSample(header *SampleHeader, payload *bytes.Buffer) (interface{}, error) {
	format := (*header).Format
	var sample interface{}

	err := utils.BinaryDecoder(payload, &((*header).SampleSequenceNumber))
	if err != nil {
		return sample, err
	}
	if format == FORMAT_RAW_PKT || format == FORMAT_ETH {
		var sourceId uint32
		err = utils.BinaryDecoder(payload, &sourceId)
		if err != nil {
			return sample, err
		}

		(*header).SourceIdType = sourceId >> 24
		(*header).SourceIdValue = sourceId & 0x00ffffff
	} else if format == FORMAT_IPV4 || format == FORMAT_IPV6 {
		err = utils.BinaryDecoder(payload, &((*header).SourceIdType), &((*header).SourceIdValue))
		if err != nil {
			return sample, err
		}
	} else {
		return nil, NewErrorDataFormat(format)
	}

	var recordsCount uint32
	var flowSample FlowSample
	var counterSample CounterSample
	var expandedFlowSample ExpandedFlowSample
	if format == FORMAT_RAW_PKT {
		flowSample = FlowSample{
			Header: *header,
		}
		err = utils.BinaryDecoder(payload, &(flowSample.SamplingRate), &(flowSample.SamplePool),
			&(flowSample.Drops), &(flowSample.Input), &(flowSample.Output), &(flowSample.FlowRecordsCount))
		if err != nil {
			return sample, err
		}
		recordsCount = flowSample.FlowRecordsCount
		flowSample.Records = make([]FlowRecord, recordsCount)
		sample = flowSample
	} else if format == FORMAT_ETH || format == FORMAT_IPV6 {
		err = utils.BinaryDecoder(payload, &recordsCount)
		if err != nil {
			return sample, err
		}
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
		err = utils.BinaryDecoder(payload, &(expandedFlowSample.SamplingRate), &(expandedFlowSample.SamplePool),
			&(expandedFlowSample.Drops), &(expandedFlowSample.InputIfFormat), &(expandedFlowSample.InputIfValue),
			&(expandedFlowSample.OutputIfFormat), &(expandedFlowSample.OutputIfValue), &(expandedFlowSample.FlowRecordsCount))
		if err != nil {
			return sample, err
		}
		recordsCount = expandedFlowSample.FlowRecordsCount
		expandedFlowSample.Records = make([]FlowRecord, recordsCount)
		sample = expandedFlowSample
	}
	for i := 0; i < int(recordsCount) && payload.Len() >= 8; i++ {
		recordHeader := RecordHeader{}
		err = utils.BinaryDecoder(payload, &(recordHeader.DataFormat), &(recordHeader.Length))
		if err != nil {
			return sample, err
		}
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
	return sample, nil
}

func DecodeMessage(payload *bytes.Buffer) (interface{}, error) {
	var version uint32
	err := utils.BinaryDecoder(payload, &version)
	if err != nil {
		return nil, err
	}
	packetV5 := Packet{}
	if version == 5 {
		packetV5.Version = version
		err = utils.BinaryDecoder(payload, &(packetV5.IPVersion))
		if err != nil {
			return packetV5, err
		}
		var ip []byte
		if packetV5.IPVersion == 1 {
			ip = make([]byte, 4)
			utils.BinaryDecoder(payload, ip)
		} else if packetV5.IPVersion == 2 {
			ip = make([]byte, 16)
			err = utils.BinaryDecoder(payload, ip)
			if err != nil {
				return packetV5, err
			}
		} else {
			return nil, NewErrorIPVersion(packetV5.IPVersion)
		}

		packetV5.AgentIP = ip
		err = utils.BinaryDecoder(payload, &(packetV5.SubAgentId), &(packetV5.SequenceNumber), &(packetV5.Uptime), &(packetV5.SamplesCount))
		if err != nil {
			return packetV5, err
		}
		packetV5.Samples = make([]interface{}, int(packetV5.SamplesCount))
		for i := 0; i < int(packetV5.SamplesCount) && payload.Len() >= 8; i++ {
			header := SampleHeader{}
			err = utils.BinaryDecoder(payload, &(header.Format), &(header.Length))
			if err != nil {
				return packetV5, err
			}
			if int(header.Length) > payload.Len() {
				break
			}
			sampleReader := bytes.NewBuffer(payload.Next(int(header.Length)))

			sample, err := DecodeSample(&header, sampleReader)
			if err != nil {
				continue
			} else {
				packetV5.Samples[i] = sample
			}
		}

		return packetV5, nil
	} else {
		return nil, NewErrorVersion(version)
	}
}
