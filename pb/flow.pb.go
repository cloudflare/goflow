// Code generated by protoc-gen-go. DO NOT EDIT.
// source: flow.proto

/*
Package flowprotob is a generated protocol buffer package.

It is generated from these files:
	flow.proto

It has these top-level messages:
	FlowMessage
*/
package flowprotob

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type FlowMessage_FlowType int32

const (
	FlowMessage_FLOWUNKNOWN FlowMessage_FlowType = 0
	FlowMessage_NFV9        FlowMessage_FlowType = 9
	FlowMessage_IPFIX       FlowMessage_FlowType = 10
	FlowMessage_SFLOW       FlowMessage_FlowType = 5
)

var FlowMessage_FlowType_name = map[int32]string{
	0:  "FLOWUNKNOWN",
	9:  "NFV9",
	10: "IPFIX",
	5:  "SFLOW",
}
var FlowMessage_FlowType_value = map[string]int32{
	"FLOWUNKNOWN": 0,
	"NFV9":        9,
	"IPFIX":       10,
	"SFLOW":       5,
}

func (x FlowMessage_FlowType) String() string {
	return proto.EnumName(FlowMessage_FlowType_name, int32(x))
}
func (FlowMessage_FlowType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 0} }

// To be deprecated
type FlowMessage_IPType int32

const (
	FlowMessage_IPUNKNOWN FlowMessage_IPType = 0
	FlowMessage_IPv4      FlowMessage_IPType = 4
	FlowMessage_IPv6      FlowMessage_IPType = 6
)

var FlowMessage_IPType_name = map[int32]string{
	0: "IPUNKNOWN",
	4: "IPv4",
	6: "IPv6",
}
var FlowMessage_IPType_value = map[string]int32{
	"IPUNKNOWN": 0,
	"IPv4":      4,
	"IPv6":      6,
}

func (x FlowMessage_IPType) String() string {
	return proto.EnumName(FlowMessage_IPType_name, int32(x))
}
func (FlowMessage_IPType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0, 1} }

type FlowMessage struct {
	Type         FlowMessage_FlowType `protobuf:"varint,1,opt,name=Type,json=type,enum=flowprotob.FlowMessage_FlowType" json:"Type,omitempty"`
	TimeRecvd    uint64               `protobuf:"varint,2,opt,name=TimeRecvd,json=timeRecvd" json:"TimeRecvd,omitempty"`
	SamplingRate uint64               `protobuf:"varint,3,opt,name=SamplingRate,json=samplingRate" json:"SamplingRate,omitempty"`
	SequenceNum  uint32               `protobuf:"varint,4,opt,name=SequenceNum,json=sequenceNum" json:"SequenceNum,omitempty"`
	// Found inside packet
	TimeFlow uint64 `protobuf:"varint,5,opt,name=TimeFlow,json=timeFlow" json:"TimeFlow,omitempty"`
	// Source/destination addresses
	SrcIP     []byte             `protobuf:"bytes,6,opt,name=SrcIP,json=srcIP,proto3" json:"SrcIP,omitempty"`
	DstIP     []byte             `protobuf:"bytes,7,opt,name=DstIP,json=dstIP,proto3" json:"DstIP,omitempty"`
	IPversion FlowMessage_IPType `protobuf:"varint,8,opt,name=IPversion,json=iPversion,enum=flowprotob.FlowMessage_IPType" json:"IPversion,omitempty"`
	// Size of the sampled packet
	Bytes   uint64 `protobuf:"varint,9,opt,name=Bytes,json=bytes" json:"Bytes,omitempty"`
	Packets uint64 `protobuf:"varint,10,opt,name=Packets,json=packets" json:"Packets,omitempty"`
	// Routing information
	RouterAddr []byte `protobuf:"bytes,11,opt,name=RouterAddr,json=routerAddr,proto3" json:"RouterAddr,omitempty"`
	NextHop    []byte `protobuf:"bytes,12,opt,name=NextHop,json=nextHop,proto3" json:"NextHop,omitempty"`
	NextHopAS  uint32 `protobuf:"varint,13,opt,name=NextHopAS,json=nextHopAS" json:"NextHopAS,omitempty"`
	// Autonomous system information
	SrcAS uint32 `protobuf:"varint,14,opt,name=SrcAS,json=srcAS" json:"SrcAS,omitempty"`
	DstAS uint32 `protobuf:"varint,15,opt,name=DstAS,json=dstAS" json:"DstAS,omitempty"`
	// Prefix size
	SrcNet uint32 `protobuf:"varint,16,opt,name=SrcNet,json=srcNet" json:"SrcNet,omitempty"`
	DstNet uint32 `protobuf:"varint,17,opt,name=DstNet,json=dstNet" json:"DstNet,omitempty"`
	// Interfaces
	SrcIf uint32 `protobuf:"varint,18,opt,name=SrcIf,json=srcIf" json:"SrcIf,omitempty"`
	DstIf uint32 `protobuf:"varint,19,opt,name=DstIf,json=dstIf" json:"DstIf,omitempty"`
	// Layer 4 protocol
	Proto uint32 `protobuf:"varint,20,opt,name=Proto,json=proto" json:"Proto,omitempty"`
	// Port for UDP and TCP
	SrcPort uint32 `protobuf:"varint,21,opt,name=SrcPort,json=srcPort" json:"SrcPort,omitempty"`
	DstPort uint32 `protobuf:"varint,22,opt,name=DstPort,json=dstPort" json:"DstPort,omitempty"`
	// IP and TCP special flags
	IPTos            uint32 `protobuf:"varint,23,opt,name=IPTos,json=iPTos" json:"IPTos,omitempty"`
	ForwardingStatus uint32 `protobuf:"varint,24,opt,name=ForwardingStatus,json=forwardingStatus" json:"ForwardingStatus,omitempty"`
	IPTTL            uint32 `protobuf:"varint,25,opt,name=IPTTL,json=iPTTL" json:"IPTTL,omitempty"`
	TCPFlags         uint32 `protobuf:"varint,26,opt,name=TCPFlags,json=tCPFlags" json:"TCPFlags,omitempty"`
	// Ethernet information
	SrcMac uint64 `protobuf:"varint,27,opt,name=SrcMac,json=srcMac" json:"SrcMac,omitempty"`
	DstMac uint64 `protobuf:"varint,28,opt,name=DstMac,json=dstMac" json:"DstMac,omitempty"`
	VlanId uint32 `protobuf:"varint,29,opt,name=VlanId,json=vlanId" json:"VlanId,omitempty"`
	// Layer 3 protocol (IPv4/IPv6/ARP/...)
	Etype uint32 `protobuf:"varint,30,opt,name=Etype,json=etype" json:"Etype,omitempty"`
}

func (m *FlowMessage) Reset()                    { *m = FlowMessage{} }
func (m *FlowMessage) String() string            { return proto.CompactTextString(m) }
func (*FlowMessage) ProtoMessage()               {}
func (*FlowMessage) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *FlowMessage) GetType() FlowMessage_FlowType {
	if m != nil {
		return m.Type
	}
	return FlowMessage_FLOWUNKNOWN
}

func (m *FlowMessage) GetTimeRecvd() uint64 {
	if m != nil {
		return m.TimeRecvd
	}
	return 0
}

func (m *FlowMessage) GetSamplingRate() uint64 {
	if m != nil {
		return m.SamplingRate
	}
	return 0
}

func (m *FlowMessage) GetSequenceNum() uint32 {
	if m != nil {
		return m.SequenceNum
	}
	return 0
}

func (m *FlowMessage) GetTimeFlow() uint64 {
	if m != nil {
		return m.TimeFlow
	}
	return 0
}

func (m *FlowMessage) GetSrcIP() []byte {
	if m != nil {
		return m.SrcIP
	}
	return nil
}

func (m *FlowMessage) GetDstIP() []byte {
	if m != nil {
		return m.DstIP
	}
	return nil
}

func (m *FlowMessage) GetIPversion() FlowMessage_IPType {
	if m != nil {
		return m.IPversion
	}
	return FlowMessage_IPUNKNOWN
}

func (m *FlowMessage) GetBytes() uint64 {
	if m != nil {
		return m.Bytes
	}
	return 0
}

func (m *FlowMessage) GetPackets() uint64 {
	if m != nil {
		return m.Packets
	}
	return 0
}

func (m *FlowMessage) GetRouterAddr() []byte {
	if m != nil {
		return m.RouterAddr
	}
	return nil
}

func (m *FlowMessage) GetNextHop() []byte {
	if m != nil {
		return m.NextHop
	}
	return nil
}

func (m *FlowMessage) GetNextHopAS() uint32 {
	if m != nil {
		return m.NextHopAS
	}
	return 0
}

func (m *FlowMessage) GetSrcAS() uint32 {
	if m != nil {
		return m.SrcAS
	}
	return 0
}

func (m *FlowMessage) GetDstAS() uint32 {
	if m != nil {
		return m.DstAS
	}
	return 0
}

func (m *FlowMessage) GetSrcNet() uint32 {
	if m != nil {
		return m.SrcNet
	}
	return 0
}

func (m *FlowMessage) GetDstNet() uint32 {
	if m != nil {
		return m.DstNet
	}
	return 0
}

func (m *FlowMessage) GetSrcIf() uint32 {
	if m != nil {
		return m.SrcIf
	}
	return 0
}

func (m *FlowMessage) GetDstIf() uint32 {
	if m != nil {
		return m.DstIf
	}
	return 0
}

func (m *FlowMessage) GetProto() uint32 {
	if m != nil {
		return m.Proto
	}
	return 0
}

func (m *FlowMessage) GetSrcPort() uint32 {
	if m != nil {
		return m.SrcPort
	}
	return 0
}

func (m *FlowMessage) GetDstPort() uint32 {
	if m != nil {
		return m.DstPort
	}
	return 0
}

func (m *FlowMessage) GetIPTos() uint32 {
	if m != nil {
		return m.IPTos
	}
	return 0
}

func (m *FlowMessage) GetForwardingStatus() uint32 {
	if m != nil {
		return m.ForwardingStatus
	}
	return 0
}

func (m *FlowMessage) GetIPTTL() uint32 {
	if m != nil {
		return m.IPTTL
	}
	return 0
}

func (m *FlowMessage) GetTCPFlags() uint32 {
	if m != nil {
		return m.TCPFlags
	}
	return 0
}

func (m *FlowMessage) GetSrcMac() uint64 {
	if m != nil {
		return m.SrcMac
	}
	return 0
}

func (m *FlowMessage) GetDstMac() uint64 {
	if m != nil {
		return m.DstMac
	}
	return 0
}

func (m *FlowMessage) GetVlanId() uint32 {
	if m != nil {
		return m.VlanId
	}
	return 0
}

func (m *FlowMessage) GetEtype() uint32 {
	if m != nil {
		return m.Etype
	}
	return 0
}

func init() {
	proto.RegisterType((*FlowMessage)(nil), "flowprotob.FlowMessage")
	proto.RegisterEnum("flowprotob.FlowMessage_FlowType", FlowMessage_FlowType_name, FlowMessage_FlowType_value)
	proto.RegisterEnum("flowprotob.FlowMessage_IPType", FlowMessage_IPType_name, FlowMessage_IPType_value)
}

func init() { proto.RegisterFile("flow.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 598 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x09, 0x6e, 0x88, 0x02, 0xff, 0x74, 0x93, 0x41, 0x6f, 0xd3, 0x4c,
	0x10, 0x86, 0xbf, 0x7c, 0x24, 0x71, 0x3c, 0x49, 0x5a, 0xb3, 0x94, 0x32, 0x94, 0x52, 0x45, 0x39,
	0x45, 0x54, 0xca, 0x01, 0x2a, 0x24, 0x04, 0x97, 0x94, 0x10, 0x61, 0xd1, 0xba, 0x96, 0x1d, 0x5a,
	0xae, 0x8e, 0xbd, 0x89, 0x22, 0x1c, 0x3b, 0x78, 0x37, 0x29, 0xfd, 0x7d, 0xfc, 0x31, 0x34, 0xb3,
	0x76, 0x5a, 0x90, 0xb8, 0xcd, 0xfb, 0xcc, 0xec, 0xec, 0xce, 0xeb, 0x31, 0xc0, 0x3c, 0xcd, 0x6f,
	0x87, 0xeb, 0x22, 0xd7, 0xb9, 0xe0, 0x98, 0xc3, 0x59, 0xff, 0x97, 0x05, 0xed, 0x49, 0x9a, 0xdf,
	0x5e, 0x4a, 0xa5, 0xa2, 0x85, 0x14, 0x67, 0x50, 0x9f, 0xde, 0xad, 0x25, 0xd6, 0x7a, 0xb5, 0xc1,
	0xde, 0xeb, 0xde, 0xf0, 0xbe, 0x74, 0xf8, 0xa0, 0x8c, 0x63, 0xaa, 0x0b, 0xea, 0xfa, 0x6e, 0x2d,
	0xc5, 0x31, 0xd8, 0xd3, 0xe5, 0x4a, 0x06, 0x32, 0xde, 0x26, 0xf8, 0x7f, 0xaf, 0x36, 0xa8, 0x07,
	0xb6, 0xae, 0x80, 0xe8, 0x43, 0x27, 0x8c, 0x56, 0xeb, 0x74, 0x99, 0x2d, 0x82, 0x48, 0x4b, 0x7c,
	0xc4, 0x05, 0x1d, 0xf5, 0x80, 0x89, 0x1e, 0xb4, 0x43, 0xf9, 0x63, 0x23, 0xb3, 0x58, 0x7a, 0x9b,
	0x15, 0xd6, 0x7b, 0xb5, 0x41, 0x37, 0x68, 0xab, 0x7b, 0x24, 0x8e, 0xa0, 0x45, 0x77, 0xd0, 0xcd,
	0xd8, 0xe0, 0x0e, 0x2d, 0x5d, 0x6a, 0x71, 0x00, 0x8d, 0xb0, 0x88, 0x5d, 0x1f, 0x9b, 0xbd, 0xda,
	0xa0, 0x13, 0x34, 0x14, 0x09, 0xa2, 0x63, 0xa5, 0x5d, 0x1f, 0x2d, 0x43, 0x13, 0x12, 0xe2, 0x03,
	0xd8, 0xae, 0xbf, 0x95, 0x85, 0x5a, 0xe6, 0x19, 0xb6, 0x78, 0xcc, 0x93, 0x7f, 0x8d, 0xe9, 0xfa,
	0x3c, 0xa4, 0xbd, 0xac, 0x0e, 0x50, 0xcf, 0xf3, 0x3b, 0x2d, 0x15, 0xda, 0xfc, 0x84, 0xc6, 0x8c,
	0x84, 0x40, 0xb0, 0xfc, 0x28, 0xfe, 0x2e, 0xb5, 0x42, 0x60, 0x6e, 0xad, 0x8d, 0x14, 0x27, 0x00,
	0x41, 0xbe, 0xd1, 0xb2, 0x18, 0x25, 0x49, 0x81, 0x6d, 0x7e, 0x08, 0x14, 0x3b, 0x42, 0x27, 0x3d,
	0xf9, 0x53, 0x7f, 0xce, 0xd7, 0xd8, 0xe1, 0xa4, 0x95, 0x19, 0x49, 0x9e, 0x96, 0x99, 0x51, 0x88,
	0x5d, 0xf6, 0xc3, 0xce, 0x2a, 0x50, 0x4e, 0x3c, 0x0a, 0x71, 0x8f, 0x33, 0x34, 0xb1, 0xa1, 0x63,
	0xa5, 0x47, 0x21, 0xee, 0x1b, 0x9a, 0x90, 0x10, 0x87, 0xd0, 0x0c, 0x8b, 0xd8, 0x93, 0x1a, 0x1d,
	0xc6, 0x4d, 0xc5, 0x8a, 0xf8, 0x58, 0x69, 0xe2, 0x8f, 0x0d, 0x4f, 0x58, 0x55, 0x6e, 0xce, 0x51,
	0xec, 0x7a, 0xbb, 0xf3, 0xca, 0xcd, 0x39, 0x3e, 0xd9, 0xf5, 0x36, 0xd4, 0x27, 0xdf, 0xf0, 0xc0,
	0x50, 0xb3, 0x61, 0x08, 0x56, 0x58, 0xc4, 0x7e, 0x5e, 0x68, 0x7c, 0xca, 0xdc, 0x52, 0x46, 0x52,
	0x66, 0xac, 0x34, 0x67, 0x0e, 0x4d, 0x26, 0x31, 0x92, 0x3a, 0xb9, 0xfe, 0x34, 0x57, 0xf8, 0xcc,
	0x74, 0x5a, 0x92, 0x10, 0xaf, 0xc0, 0x99, 0xe4, 0xc5, 0x6d, 0x54, 0x24, 0xcb, 0x6c, 0x11, 0xea,
	0x48, 0x6f, 0x14, 0x22, 0x17, 0x38, 0xf3, 0xbf, 0x78, 0xd9, 0x61, 0x7a, 0x81, 0xcf, 0x77, 0x1d,
	0xa6, 0x17, 0xbc, 0x37, 0x1f, 0xfd, 0x49, 0x1a, 0x2d, 0x14, 0x1e, 0x71, 0xa2, 0xa5, 0x4b, 0x5d,
	0x3a, 0x73, 0x19, 0xc5, 0xf8, 0x82, 0x3f, 0x1b, 0x39, 0x73, 0x19, 0xc5, 0xa5, 0x33, 0xc4, 0x8f,
	0x0d, 0x4f, 0x58, 0x11, 0xbf, 0x4e, 0xa3, 0xcc, 0x4d, 0xf0, 0xa5, 0x71, 0x6c, 0xcb, 0x8a, 0x6e,
	0xfe, 0x44, 0x3f, 0x02, 0x9e, 0x98, 0x9b, 0x25, 0x89, 0xfe, 0x7b, 0x68, 0x55, 0xff, 0x89, 0xd8,
	0x87, 0xf6, 0xe4, 0xe2, 0xea, 0xe6, 0xab, 0xf7, 0xc5, 0xbb, 0xba, 0xf1, 0x9c, 0xff, 0x44, 0x0b,
	0xea, 0xde, 0xe4, 0xfa, 0x9d, 0x63, 0x0b, 0x9b, 0x9e, 0x3d, 0x71, 0xbf, 0x39, 0x40, 0x61, 0x48,
	0x65, 0x4e, 0xa3, 0x7f, 0x0a, 0x4d, 0xb3, 0x7d, 0xa2, 0x4b, 0x0b, 0xfb, 0xc7, 0x41, 0xd7, 0xdf,
	0x9e, 0x39, 0xf5, 0x32, 0x7a, 0xeb, 0x34, 0xcf, 0x4f, 0xe1, 0x28, 0xce, 0x57, 0xc3, 0x38, 0xcd,
	0x37, 0xc9, 0x3c, 0x8d, 0x0a, 0x39, 0xcc, 0xa4, 0xe6, 0xa5, 0x8e, 0x16, 0x8b, 0xf3, 0xee, 0x83,
	0x95, 0xf6, 0x67, 0xb3, 0x26, 0x7f, 0xa3, 0x37, 0xbf, 0x03, 0x00, 0x00, 0xff, 0xff, 0x3f, 0xb3,
	0xab, 0x2d, 0x13, 0x04, 0x00, 0x00,
}
