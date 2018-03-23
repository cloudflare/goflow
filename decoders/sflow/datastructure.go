package sflow

type SampledHeader struct {
	Protocol       uint32
	FrameLength    uint32
	Stripped       uint32
	OriginalLength uint32
	HeaderData     []byte
}

type SampledEthernet struct {
	Length  uint32
	SrcMac  []byte
	DstMac  []byte
	EthType uint32
}

type SampledIP_Base struct {
	Length   uint32
	Protocol uint32
	SrcIP    []byte
	DstIP    []byte
	SrcPort  uint32
	DstPort  uint32
	TcpFlags uint32
}

type SampledIPv4 struct {
	Base SampledIP_Base
	Tos  uint32
}

type SampledIPv6 struct {
	Base     SampledIP_Base
	Priority uint32
}

type ExtendedSwitch struct {
	SrcVlan     uint32
	SrcPriority uint32
	DstVlan     uint32
	DstPriority uint32
}

type ExtendedRouter struct {
	NextHopIPVersion uint32
	NextHop          []byte
	SrcMaskLen       uint32
	DstMaskLen       uint32
}

type ExtendedGateway struct {
	NextHopIPVersion  uint32
	NextHop           []byte
	AS                uint32
	SrcAS             uint32
	SrcPeerAS         uint32
	ASDestinations    uint32
	ASPathType        uint32
	ASPathLength      uint32
	ASPath            []uint32
	CommunitiesLength uint32
	Communities       []uint32
	LocalPref         uint32
}

type IfCounters struct {
	IfIndex            uint32
	IfType             uint32
	IfSpeed            uint64
	IfDirection        uint32
	IfStatus           uint32
	IfInOctets         uint64
	IfInUcastPkts      uint32
	IfInMulticastPkts  uint32
	IfInBroadcastPkts  uint32
	IfInDiscards       uint32
	IfInErrors         uint32
	IfInUnknownProtos  uint32
	IfOutOctets        uint64
	IfOutUcastPkts     uint32
	IfOutMulticastPkts uint32
	IfOutBroadcastPkts uint32
	IfOutDiscards      uint32
	IfOutErrors        uint32
	IfPromiscuousMode  uint32
}

type EthernetCounters struct {
	Dot3StatsAlignmentErrors           uint32
	Dot3StatsFCSErrors                 uint32
	Dot3StatsSingleCollisionFrames     uint32
	Dot3StatsMultipleCollisionFrames   uint32
	Dot3StatsSQETestErrors             uint32
	Dot3StatsDeferredTransmissions     uint32
	Dot3StatsLateCollisions            uint32
	Dot3StatsExcessiveCollisions       uint32
	Dot3StatsInternalMacTransmitErrors uint32
	Dot3StatsCarrierSenseErrors        uint32
	Dot3StatsFrameTooLongs             uint32
	Dot3StatsInternalMacReceiveErrors  uint32
	Dot3StatsSymbolErrors              uint32
}
