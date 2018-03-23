package sflow

type Packet struct {
	Version        uint32
	IPVersion      uint32
	AgentIP        []byte
	SubAgentId     uint32
	SequenceNumber uint32
	Uptime         uint32
	SamplesCount   uint32
	Samples        []interface{}
}

type SampleHeader struct {
	Format uint32
	Length uint32

	SampleSequenceNumber uint32
	SourceIdType         uint32
	SourceIdValue        uint32
}

type FlowSample struct {
	Header SampleHeader

	SamplingRate     uint32
	SamplePool       uint32
	Drops            uint32
	Input            uint32
	Output           uint32
	FlowRecordsCount uint32
	Records          []FlowRecord
}

type CounterSample struct {
	Header SampleHeader

	CounterRecordsCount uint32
	Records             []CounterRecord
}

type ExpandedFlowSample struct {
	Header SampleHeader

	SamplingRate     uint32
	SamplePool       uint32
	Drops            uint32
	InputIfFormat    uint32
	InputIfValue     uint32
	OutputIfFormat   uint32
	OutputIfValue    uint32
	FlowRecordsCount uint32
	Records          []FlowRecord
}

type RecordHeader struct {
	DataFormat uint32
	Length     uint32
}

type FlowRecord struct {
	Header RecordHeader
	Data   interface{}
}

type CounterRecord struct {
	Header RecordHeader
	Data   interface{}
}
