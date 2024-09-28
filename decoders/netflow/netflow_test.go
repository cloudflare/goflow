package netflow

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFlowMessage_Decode(t *testing.T) {
	f := &FlowMessage{}
	templates := CreateTemplateSystem()

	// netflow packet
	pkt1 := bytes.NewBuffer(netflowTestPackets[1].Data[42:])
	err := f.Decode(pkt1, templates)
	assert.NoError(t, err)

	assert.Equal(t, uint16(9), f.PacketNFv9.Version)
	assert.Equal(t, uint16(26), f.PacketNFv9.Count)
	assert.Equal(t, uint32(2935025008), f.PacketNFv9.SystemUptime)
	assert.Equal(t, uint32(1565290402), f.PacketNFv9.UnixSeconds)
	assert.Equal(t, uint32(3076483882), f.PacketNFv9.SequenceNumber)
	assert.Equal(t, uint32(200), f.PacketNFv9.SourceId)

	assert.Equal(t, 1, len(f.PacketNFv9.TemplateFS))
	assert.Equal(t, 1, len(f.PacketNFv9.DataFS))

	nfTempFlowset := f.PacketNFv9.TemplateFS[0]
	nfDataFlowSet := f.PacketNFv9.DataFS[0]
	assert.Equal(t, 4, len(nfTempFlowset.Records))
	assert.Equal(t, 22, len(nfDataFlowSet.Records))

	// ipfix data template packet
	pkt2 := bytes.NewBuffer(ipfixTestPackets[0].Data[42:])
	err = f.Decode(pkt2, templates)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(f.PacketIPFIX.TemplateFS))
	ipxTempFlowSet := f.PacketIPFIX.TemplateFS[0]
	assert.Equal(t, 1, len(ipxTempFlowSet.Records))

	// ipfix data records packet
	pkt3 := bytes.NewBuffer(ipfixTestPackets[2].Data[42:])
	err = f.Decode(pkt3, templates)
	assert.NoError(t, err)

	assert.Equal(t, uint16(10), f.PacketIPFIX.Version)
	assert.Equal(t, uint16(96), f.PacketIPFIX.Length)
	assert.Equal(t, uint32(1480450137), f.PacketIPFIX.ExportTime)
	assert.Equal(t, uint32(3812), f.PacketIPFIX.SequenceNumber)
	assert.Equal(t, uint32(0), f.PacketIPFIX.ObservationDomainId)
	assert.Equal(t, 1, len(f.PacketIPFIX.DataFS))

	// unknown netflow/ipfix version
	pkt4 := make([]byte, len(ipfixTestPackets[2].Data[42:]))
	copy(pkt4, ipfixTestPackets[2].Data[42:])
	pkt4[1] = 5

	err = f.Decode(bytes.NewBuffer(pkt4), templates)
	assert.Error(t, err)

	// uncomplete ipfix packet
	pkt5 := bytes.NewBuffer(ipfixTestPackets[2].Data[42:50])
	err = f.Decode(pkt5, templates)
	assert.Error(t, err)
}

func TestFlowMessage_DecodeIPFIXPacket(t *testing.T) {
	f := &FlowMessage{
		PacketIPFIX: IPFIXPacket{Length: 116, ObservationDomainId: 0},
		buf:         &bytes.Buffer{},
	}
	templates := CreateTemplateSystem()

	// ipfix data template packet
	pkt1 := bytes.NewBuffer(ipfixTestPackets[0].Data[58:])
	err := f.DecodeIPFIXPacket(pkt1, templates)
	assert.NoError(t, err)

	tempFlowSet := f.PacketIPFIX.TemplateFS[0]

	assert.Equal(t, uint16(2), tempFlowSet.Id)
	assert.Equal(t, uint16(100), tempFlowSet.Length)
	assert.Equal(t, 23, len(tempFlowSet.Records[0].Fields))

	// ipfix data records packet
	f.PacketIPFIX.Length = 96

	pkt2 := bytes.NewBuffer(ipfixTestPackets[2].Data[58:])
	err = f.DecodeIPFIXPacket(pkt2, templates)
	assert.NoError(t, err)

	dataFS := f.PacketIPFIX.DataFS[0]
	assert.Equal(t, uint16(307), dataFS.Id)
	assert.Equal(t, uint16(80), dataFS.Length)
	assert.Equal(t, 1, len(dataFS.Records))

	// packet without template and empty NetflowTemplateSystem
	pkt3 := bytes.NewBuffer(ipfixTestPackets[2].Data[58:])
	err = f.DecodeIPFIXPacket(pkt3, CreateTemplateSystem())
	assert.Error(t, err)

	// packet with wrong flowSet header id
	pkt4 := make([]byte, len(ipfixTestPackets[2].Data[58:]))
	copy(pkt4, ipfixTestPackets[2].Data[58:])
	pkt4[1] = 30
	err = f.DecodeIPFIXPacket(bytes.NewBuffer(pkt4), templates)
	assert.Error(t, err)

	// packet with wrong flowSet length
	pkt5 := make([]byte, len(ipfixTestPackets[2].Data[58:]))
	copy(pkt5, ipfixTestPackets[2].Data[58:])
	pkt5[3] = 1
	err = f.DecodeIPFIXPacket(bytes.NewBuffer(pkt5), templates)
	assert.Error(t, err)
}

func TestFlowMessage_DecodeNFv9Packet(t *testing.T) {
	templates := CreateTemplateSystem()
	f := &FlowMessage{
		PacketNFv9: NFv9Packet{Count: 26, SourceId: 200},
		buf:        &bytes.Buffer{},
	}

	// packet with template and data flowSets
	pkt1 := bytes.NewBuffer(netflowTestPackets[1].Data[62:])
	err := f.DecodeNFv9Packet(pkt1, templates)
	assert.NoError(t, err)

	// packet without template and empty NetFlowTemplateSystem
	pkt2 := bytes.NewBuffer(netflowTestPackets[1].Data[206:])
	err = f.DecodeNFv9Packet(pkt2, CreateTemplateSystem())
	assert.Error(t, err)

	// incomplete packet
	pkt3 := bytes.NewBuffer(netflowTestPackets[1].Data[62:100])
	err = f.DecodeNFv9Packet(pkt3, templates)
	assert.Error(t, err)

	// packet with wrong flowSet header id
	pkt4 := make([]byte, len(netflowTestPackets[1].Data[62:]))
	copy(pkt4, netflowTestPackets[1].Data[62:])
	pkt4[1] = 30
	err = f.DecodeNFv9Packet(bytes.NewBuffer(pkt4), templates)
	assert.Error(t, err)

	// packet with wrong flowSet length
	pkt5 := make([]byte, len(netflowTestPackets[1].Data[62:]))
	copy(pkt5, netflowTestPackets[1].Data[62:])
	pkt5[3] = 1
	err = f.DecodeNFv9Packet(bytes.NewBuffer(pkt5), templates)
	assert.Error(t, err)
}

func TestDecodeTemplateSet(t *testing.T) {
	fs := TemplateFlowSet{}

	// packet without template flowset
	pkt0 := bytes.NewBuffer(netflowTestPackets[0].Data[42:])
	err := DecodeTemplateSet(pkt0, &fs)
	assert.Error(t, err)

	// template flowSet packet
	pkt1 := bytes.NewBuffer(netflowTestPackets[1].Data[66:206])
	err = DecodeTemplateSet(pkt1, &fs)
	assert.NoError(t, err)
	assert.Equal(t, 4, len(fs.Records))

	// first template record
	record := fs.Records[0]
	assert.Equal(t, uint16(259), record.TemplateId)
	assert.Equal(t, uint16(9), record.FieldCount)
	assert.Equal(t, 9, len(record.Fields))

	// last template record
	record = fs.Records[3]
	assert.Equal(t, uint16(256), record.TemplateId)
	assert.Equal(t, uint16(12), record.FieldCount)
	assert.Equal(t, 12, len(record.Fields))

	// zero field count
	pkt2 := make([]byte, len(netflowTestPackets[1].Data[66:206]))
	copy(pkt2, netflowTestPackets[1].Data[66:206])
	pkt2[3] = 0

	err = DecodeTemplateSet(bytes.NewBuffer(pkt2), &fs)
	assert.Error(t, err)
	assert.Equal(t, &ErrorDecodingNetFlow{msg: "error decoding TemplateSet: zero count."}, err)
}

func TestDecodeIPFIXOptionsTemplateSet(t *testing.T) {
	ts := IPFIXOptionsTemplateFlowSet{}

	// ipfix options template packet
	pkt1 := bytes.NewBuffer(ipfixTestPackets[1].Data[62:])

	err := DecodeIPFIXOptionsTemplateSet(pkt1, &ts)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(ts.Records))

	record := ts.Records[0]
	assert.Equal(t, uint16(308), record.TemplateId)
	assert.Equal(t, uint16(3), record.FieldCount)
	assert.Equal(t, uint16(1), record.ScopeFieldCount)

	// negative length
	pkt2 := make([]byte, len(ipfixTestPackets[1].Data[62:]))
	copy(pkt2, ipfixTestPackets[1].Data[62:])
	pkt2[3] = 0

	err = DecodeIPFIXOptionsTemplateSet(bytes.NewBuffer(pkt2), &ts)
	assert.Error(t, err)

	// incomplete packet
	pkt3 := bytes.NewBuffer(ipfixTestPackets[1].Data[62:70])
	err = DecodeIPFIXOptionsTemplateSet(pkt3, &ts)
	assert.Error(t, err)
}

func TestDecodeDataSet(t *testing.T) {
	fs := DataFlowSet{}

	// type and length of a single value in a netflow Data Record
	nfListFields := []Field{{8, 4, 0}, {225, 4, 0}, {12, 4, 0}, {226, 4, 0}, {7, 2, 0}, {227, 2, 0}, {11, 2, 0}, {228, 2, 0}, {234, 4, 0}, {4, 1, 0}, {230, 1, 0}, {323, 8, 0}}

	// type and length of a single value in ipfix Flow Data Record
	ipxListFields := []Field{{8, 4, 0}, {12, 4, 0}, {5, 1, 0}, {4, 1, 0}, {7, 2, 0}, {11, 2, 0}, {32, 2, 0}, {10, 4, 0}, {16, 4, 0}, {17, 4, 0}, {18, 4, 0}, {14, 4, 0}, {1, 4, 0}, {2, 4, 0}, {22, 4, 0}, {21, 4, 0}, {15, 4, 0}, {9, 1, 0}, {13, 1, 0}, {6, 1, 0}, {60, 1, 0}, {152, 8, 0}, {153, 8, 0}}

	// netflow data flowset
	nfData := bytes.NewBuffer(netflowTestPackets[1].Data[210:])
	err := DecodeDataSet(nfData, nfListFields, &fs)
	assert.NoError(t, err)
	assert.Equal(t, 22, len(fs.Records))

	// ipfix data flowset
	ipxData := bytes.NewBuffer(ipfixTestPackets[2].Data[62:])
	err = DecodeDataSet(ipxData, ipxListFields, &fs)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(fs.Records))

	flow := fs.Records[0]
	assert.Equal(t, 23, len(flow.Values))
}

func TestDecodeDataSetUsingFields(t *testing.T) {
	// type and length of a single value in a netflow Data Record
	nfListFields := []Field{{8, 4, 0}, {225, 4, 0}, {12, 4, 0}, {226, 4, 0}, {7, 2, 0}, {227, 2, 0}, {11, 2, 0}, {228, 2, 0}, {234, 4, 0}, {4, 1, 0}, {230, 1, 0}, {323, 8, 0}}

	// type and length of a single value in ipfix Flow Data Record
	ipxListFields := []Field{{8, 4, 0}, {12, 4, 0}, {5, 1, 0}, {4, 1, 0}, {7, 2, 0}, {11, 2, 0}, {32, 2, 0}, {10, 4, 0}, {16, 4, 0}, {17, 4, 0}, {18, 4, 0}, {14, 4, 0}, {1, 4, 0}, {2, 4, 0}, {22, 4, 0}, {21, 4, 0}, {15, 4, 0}, {9, 1, 0}, {13, 1, 0}, {6, 1, 0}, {60, 1, 0}, {152, 8, 0}, {153, 8, 0}}

	dr := DataRecord{}

	// netflow data flow record
	data1 := bytes.NewBuffer(netflowTestPackets[1].Data[210:248])
	err := DecodeDataRecordFields(data1, nfListFields, &dr.Values)
	assert.NoError(t, err)
	assert.Equal(t, 12, len(dr.Values))

	flow := dr.Values[0] // first record
	assert.Equal(t, uint16(8), flow.Type)
	assert.Equal(t, []byte{0x0a, 0xe5, 0x40, 0xdb}, flow.Value)

	flow = dr.Values[11] // last record
	assert.Equal(t, uint16(323), flow.Type)
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x6c, 0x72, 0x94, 0x12, 0x69}, flow.Value)

	// ipfix data flow record
	data2 := bytes.NewBuffer(ipfixTestPackets[2].Data[62:])
	err = DecodeDataRecordFields(data2, ipxListFields, &dr.Values)
	assert.NoError(t, err)
	assert.Equal(t, 23, len(dr.Values))

	flow = dr.Values[0] // first record

	assert.Equal(t, uint16(8), flow.Type)
	assert.Equal(t, []byte{0x46, 0x01, 0x73, 0x01}, flow.Value)

	flow = dr.Values[22] // last record
	assert.Equal(t, uint16(153), flow.Type)
	assert.Equal(t, []byte{0x00, 0x00, 0x01, 0x58, 0xb1, 0xb3, 0xe1, 0x4d}, flow.Value)

	// incomplete data for template
	data3 := bytes.NewBuffer(netflowTestPackets[1].Data[210:247])
	err = DecodeDataRecordFields(data3, nfListFields, &dr.Values)
	assert.Error(t, err)
}
