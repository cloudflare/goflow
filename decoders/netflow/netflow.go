package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/cloudflare/goflow/v3/decoders/utils"
)

type FlowBaseTemplateSet map[uint16]map[uint32]map[uint16]interface{}

type NetFlowTemplateSystem interface {
	GetTemplate(version uint16, obsDomainId uint32, templateId uint16) (interface{}, error)
	AddTemplate(version uint16, obsDomainId uint32, template interface{})
}

// DecodeNFv9OptionsTemplateSet decodes the options template data that describe
// structure of IPFIX Options Data Records.
func DecodeNFv9OptionsTemplateSet(payload *bytes.Buffer, ts *NFv9OptionsTemplateFlowSet) error {
	ts.Records = ts.Records[:cap(ts.Records)]

	i := 0
	for payload.Len() >= 4 {
		if i >= len(ts.Records) {
			ts.Records = append(ts.Records, NFv9OptionsTemplateRecord{})
		}

		record := &ts.Records[i]
		if !record.ReadFrom(payload) {
			return fmt.Errorf("decode nfv9 options templateSet: %v", io.ErrUnexpectedEOF)
		}

		sizeScope := int(record.ScopeLength) / 4
		sizeOptions := int(record.OptionLength) / 4
		if sizeScope < 0 || sizeOptions < 0 {
			return NewErrorDecodingNetFlow("error decoding OptionsTemplateSet: negative length.")
		}

		record.Scopes = record.Scopes[:cap(record.Scopes)]
		if len(record.Scopes) < sizeScope {
			record.Scopes = append(record.Scopes, make([]Field, sizeScope-len(record.Scopes))...)
		}

		for j := 0; j < sizeScope; j++ {
			if !record.Scopes[j].ReadFrom(payload) {
				return fmt.Errorf("decode nfv9 options templateSet: %v", io.ErrUnexpectedEOF)
			}
		}
		record.Scopes = record.Scopes[:sizeScope]

		record.Options = record.Options[:cap(record.Options)]
		if len(record.Options) < sizeOptions {
			record.Options = append(record.Options, make([]Field, sizeOptions-len(record.Options))...)
		}

		for k := 0; k < sizeOptions; k++ {
			if !record.Options[k].ReadFrom(payload) {
				return fmt.Errorf("decode nfv9 options templateSet: %v", io.ErrUnexpectedEOF)
			}
		}
		record.Options = record.Options[:sizeOptions]

		i++
	}
	ts.Records = ts.Records[:i]
	return nil
}

// DecodeIPFIXOptionsTemplateSet decodes the options template data that describe
// structure of NetFlow Options Data Records.
func DecodeIPFIXOptionsTemplateSet(payload *bytes.Buffer, ts *IPFIXOptionsTemplateFlowSet) error {
	ts.Records = ts.Records[:cap(ts.Records)]

	i := 0
	for payload.Len() >= 4 {
		if i >= len(ts.Records) {
			ts.Records = append(ts.Records, IPFIXOptionsTemplateRecord{})
		}

		optsTemplateRecord := &ts.Records[i]
		if !optsTemplateRecord.ReadFrom(payload) {
			return fmt.Errorf("decode ipfix options templateSet: %v", io.ErrUnexpectedEOF)
		}

		if len(optsTemplateRecord.Scopes) < int(optsTemplateRecord.ScopeFieldCount) {
			optsTemplateRecord.Scopes = append(optsTemplateRecord.Scopes, make([]Field, int(optsTemplateRecord.ScopeFieldCount)-len(optsTemplateRecord.Scopes))...)
		}

		for j := 0; j < int(optsTemplateRecord.ScopeFieldCount); j++ {
			if !optsTemplateRecord.Scopes[j].ReadFrom(payload) {
				return fmt.Errorf("decode ipfix options templateSet: %v", io.ErrUnexpectedEOF)
			}
		}
		optsTemplateRecord.Scopes = optsTemplateRecord.Scopes[:int(optsTemplateRecord.ScopeFieldCount)]

		optionsSize := int(optsTemplateRecord.FieldCount) - int(optsTemplateRecord.ScopeFieldCount)
		if optionsSize < 0 {
			return NewErrorDecodingNetFlow("error decoding OptionsTemplateSet: negative length.")
		}

		if len(optsTemplateRecord.Options) < optionsSize {
			optsTemplateRecord.Options = append(optsTemplateRecord.Options, make([]Field, optionsSize-len(optsTemplateRecord.Options))...)
		}

		for k := 0; k < optionsSize; k++ {
			if !optsTemplateRecord.Options[k].ReadFrom(payload) {
				return fmt.Errorf("decode ipfix options templateSet: %v", io.ErrUnexpectedEOF)
			}
		}
		optsTemplateRecord.Options = optsTemplateRecord.Options[:optionsSize]

		i++
	}
	ts.Records = ts.Records[:i]
	return nil
}

// DecodeTemplateSet decodes the template data that describe structure of Data Records (actual netflow/ipfix data).
func DecodeTemplateSet(payload *bytes.Buffer, ts *TemplateFlowSet) error {
	ts.Records = ts.Records[:cap(ts.Records)]

	i := 0
	for payload.Len() >= 4 {
		if i >= len(ts.Records) {
			ts.Records = append(ts.Records, TemplateRecord{})
		}

		record := &ts.Records[i]
		if !record.ReadFrom(payload) {
			return fmt.Errorf("decode TemplateSet: %v", io.ErrUnexpectedEOF)
		}

		if record.FieldCount == 0 {
			return NewErrorDecodingNetFlow("error decoding TemplateSet: zero count.")
		}

		record.Fields = record.Fields[:cap(record.Fields)]

		if len(record.Fields) < int(record.FieldCount) {
			record.Fields = append(record.Fields, make([]Field, int(record.FieldCount)-len(record.Fields))...)
		}

		for j := 0; j < int(record.FieldCount); j++ {
			if !record.Fields[j].ReadFrom(payload) {
				return fmt.Errorf("decode TemplateSet: %v", io.ErrUnexpectedEOF)
			}
		}
		record.Fields = record.Fields[:int(record.FieldCount)]
		i++
	}
	ts.Records = ts.Records[:i]
	return nil
}

func GetTemplateSize(template []Field) int {
	sum := 0
	for _, templateField := range template {
		sum += int(templateField.Length)
	}
	return sum
}

// DecodeDataRecordFields decodes the fields(type and value) of DataRecord.
func DecodeDataRecordFields(payload *bytes.Buffer, listFields []Field, record *[]DataField) error {
	*record = (*record)[:cap(*record)]
	if len(*record) < len(listFields) {
		*record = append(*record, make([]DataField, len(listFields)-len(*record))...)
	}

	var ok bool
	for i, templateField := range listFields {

		l := int(templateField.Length)

		if templateField.IsVariableLength() {
			if l, ok = getVariableLength(payload); !ok {
				return fmt.Errorf("decode DataRecordFields: invalid variable-length: %d", l)
			}
		}

		// XXX: Retaining a slice returned by Next() may be unsafe according to
		// method's documentation as it may be invalidated by future Read call.
		value := payload.Next(l)
		if len(value) < l {
			return fmt.Errorf("decode dataset: there are fewer than %d bytes in the buffer", l)
		}

		(*record)[i].Type = templateField.Type
		(*record)[i].Value = value
	}
	*record = (*record)[:len(listFields)]
	return nil
}

func getVariableLength(payload *bytes.Buffer) (int, bool) {
	b, err := payload.ReadByte()
	if err != nil {
		return 0, false
	}

	// RFC 7011 Sec. 7.Variable-Length Information Element.
	if b != 0xff {
		return int(b), true
	}

	// RFC 7011 Sec. 7.Variable-Length Information Element:
	// The length may also be encoded into 3 octets before the Information
	// Element, allowing the length of the Information Element to be greater
	// than or equal to 255 octets. In this case, the first octet of the Length
	// field MUST be 255, and the length is carried in the second and third
	// octets.
	length := payload.Next(2)
	if len(length) < 2 {
		return 0, false
	}

	return int(binary.BigEndian.Uint16(length)), true
}

type ErrorTemplateNotFound struct {
	version      uint16
	obsDomainId  uint32
	templateId   uint16
	typeTemplate string
}

func NewErrorTemplateNotFound(version uint16, obsDomainId uint32, templateId uint16, typeTemplate string) *ErrorTemplateNotFound {
	return &ErrorTemplateNotFound{
		version:      version,
		obsDomainId:  obsDomainId,
		templateId:   templateId,
		typeTemplate: typeTemplate,
	}
}

func (e *ErrorTemplateNotFound) Error() string {
	return fmt.Sprintf("no %v template %v found for and domain id %v", e.typeTemplate, e.templateId, e.obsDomainId)
}

type ErrorVersion struct {
	version uint16
}

func NewErrorVersion(version uint16) *ErrorVersion {
	return &ErrorVersion{
		version: version,
	}
}

func (e *ErrorVersion) Error() string {
	return fmt.Sprintf("unknown NetFlow version %v (only decodes v9 and v10/IPFIX)", e.version)
}

type ErrorFlowId struct {
	id uint16
}

func NewErrorFlowId(id uint16) *ErrorFlowId {
	return &ErrorFlowId{
		id: id,
	}
}

func (e *ErrorFlowId) Error() string {
	return fmt.Sprintf("unknown flow id %v (templates < 256, data >= 256)", e.id)
}

type ErrorDecodingNetFlow struct {
	msg string
}

func NewErrorDecodingNetFlow(msg string) *ErrorDecodingNetFlow {
	return &ErrorDecodingNetFlow{
		msg: msg,
	}
}

func (e *ErrorDecodingNetFlow) Error() string {
	return fmt.Sprintf("error decoding NetFlow: %v", e.msg)
}

// DecodeOptionsDataSet decodes the options data record ("meta-data" about the netflow/ipfix process itself).
func DecodeOptionsDataSet(payload *bytes.Buffer, fs *OptionsDataFlowSet, listFieldsScopes, listFieldsOption []Field) error {
	fs.Records = fs.Records[:cap(fs.Records)]

	listFieldsScopesSize := GetTemplateSize(listFieldsScopes)
	listFieldsOptionSize := GetTemplateSize(listFieldsOption)

	i := 0
	for payload.Len() >= listFieldsScopesSize+listFieldsOptionSize {
		if i >= len(fs.Records) {
			fs.Records = append(fs.Records, OptionsDataRecord{})
		}

		record := &fs.Records[i]
		payloadLim := bytes.NewBuffer(payload.Next(listFieldsScopesSize))

		if err := DecodeDataRecordFields(payloadLim, listFieldsScopes, &record.ScopesValues); err != nil {
			return fmt.Errorf("decode options dataSet: %v", err)
		}

		payloadLim = bytes.NewBuffer(payload.Next(listFieldsOptionSize))
		if err := DecodeDataRecordFields(payloadLim, listFieldsOption, &record.OptionsValues); err != nil {
			return fmt.Errorf("decode options dataSet: %v", err)
		}

		i++
	}
	fs.Records = fs.Records[:i]
	return nil
}

// DecodeDataSet decodes the Data Records (actual netflow/ipfix data).
func DecodeDataSet(payload *bytes.Buffer, listFields []Field, flowSet *DataFlowSet) error {
	flowSet.Records = flowSet.Records[:cap(flowSet.Records)]

	i := 0
	for payload.Len() > 0 {
		if i >= len(flowSet.Records) {
			flowSet.Records = append(flowSet.Records, DataRecord{})
		}

		datafields := &flowSet.Records[i].Values
		if err := DecodeDataRecordFields(payload, listFields, datafields); err != nil {
			return err
		}

		i++
	}
	flowSet.Records = flowSet.Records[:i]
	return nil
}

func (ts *BasicTemplateSystem) GetTemplates() map[uint16]map[uint32]map[uint16]interface{} {
	ts.templateslock.RLock()
	tmp := ts.templates
	ts.templateslock.RUnlock()
	return tmp
}

func (ts *BasicTemplateSystem) AddTemplate(version uint16, obsDomainId uint32, template interface{}) {
	ts.templateslock.Lock()
	_, exists := ts.templates[version]
	if !exists {
		ts.templates[version] = make(map[uint32]map[uint16]interface{})
	}
	_, exists = ts.templates[version][obsDomainId]
	if !exists {
		ts.templates[version][obsDomainId] = make(map[uint16]interface{})
	}
	var templateId uint16
	switch templateIdConv := template.(type) {
	case IPFIXOptionsTemplateRecord:
		templateId = templateIdConv.TemplateId
	case NFv9OptionsTemplateRecord:
		templateId = templateIdConv.TemplateId
	case TemplateRecord:
		templateId = templateIdConv.TemplateId
	}
	ts.templates[version][obsDomainId][templateId] = template
	ts.templateslock.Unlock()
}

func (ts *BasicTemplateSystem) GetTemplate(version uint16, obsDomainId uint32, templateId uint16) (interface{}, error) {
	ts.templateslock.RLock()
	templatesVersion, okver := ts.templates[version]
	if okver {
		templatesObsDom, okobs := templatesVersion[obsDomainId]
		if okobs {
			template, okid := templatesObsDom[templateId]
			if okid {
				ts.templateslock.RUnlock()
				return template, nil
			}
			ts.templateslock.RUnlock()
			return nil, NewErrorTemplateNotFound(version, obsDomainId, templateId, "info")
		}
		ts.templateslock.RUnlock()
		return nil, NewErrorTemplateNotFound(version, obsDomainId, templateId, "info")
	}
	ts.templateslock.RUnlock()
	return nil, NewErrorTemplateNotFound(version, obsDomainId, templateId, "info")
}

type BasicTemplateSystem struct {
	templates     FlowBaseTemplateSet
	templateslock *sync.RWMutex
}

func CreateTemplateSystem() *BasicTemplateSystem {
	ts := &BasicTemplateSystem{
		templates:     make(FlowBaseTemplateSet),
		templateslock: &sync.RWMutex{},
	}
	return ts
}

// FlowMessage processes the message(parses, and stores network information).
type FlowMessage struct {
	// Version is version of netflow/ipfix records exported in this packet.
	Version     uint16
	PacketNFv9  NFv9Packet
	PacketIPFIX IPFIXPacket

	fsheader FlowSetHeader
	buf      *bytes.Buffer
}

// Decode decodes and collects the message in netflow/ipfix protocol format.
func (f *FlowMessage) Decode(payload *bytes.Buffer, templates NetFlowTemplateSystem) error {
	if f.buf == nil {
		f.buf = &bytes.Buffer{}
	}

	if !utils.ReadUint16FromBuffer(payload, &f.Version) {
		return io.ErrUnexpectedEOF
	}

	if f.Version == netflow {
		if !f.PacketNFv9.ReadFrom(payload) {
			return fmt.Errorf("decode packet version: %v", io.ErrUnexpectedEOF)
		}
		f.PacketNFv9.Version = f.Version

		if err := f.DecodeNFv9Packet(payload, templates); err != nil {
			return err
		}
	} else if f.Version == ipfix {
		if !f.PacketIPFIX.ReadFrom(payload) {
			return fmt.Errorf("decode packet header: %v", io.ErrUnexpectedEOF)
		}
		f.PacketIPFIX.Version = f.Version

		if err := f.DecodeIPFIXPacket(payload, templates); err != nil {
			return err
		}
	} else {
		return NewErrorVersion(f.Version)
	}
	return nil
}

// DecodeNFv9Packet decodes and collects the message in netflow protocol format.
func (f *FlowMessage) DecodeNFv9Packet(payload *bytes.Buffer, templates NetFlowTemplateSystem) error {
	var (
		nfDataFSidx, nfTemplateFSidx, nfOptsTemplateFSidx, nfOptsDataFSidx int
	)

	for i := 0; i < int(f.PacketNFv9.Count) && payload.Len() > 0; i++ {
		f.fsheader.ReadFrom(payload)

		nextrelpos := int(f.fsheader.Length) - flowSetHeaderSize
		if nextrelpos < 0 {
			return NewErrorDecodingNetFlow("error decoding packet: non-terminated stream.")
		}

		if f.fsheader.Id == nfv9TemplateFlowSetID {
			f.buf.Reset()
			f.buf.Write(payload.Next(nextrelpos))

			f.PacketNFv9.TemplateFS = f.PacketNFv9.TemplateFS[:cap(f.PacketNFv9.TemplateFS)]
			if nfTemplateFSidx >= len(f.PacketNFv9.TemplateFS) {
				f.PacketNFv9.TemplateFS = append(f.PacketNFv9.TemplateFS, TemplateFlowSet{})
			}

			ts := &f.PacketNFv9.TemplateFS[nfTemplateFSidx]
			if err := DecodeTemplateSet(f.buf, ts); err != nil {
				return fmt.Errorf("decode netflow packet: %v", err)
			}

			ts.FlowSetHeader = f.fsheader

			if templates != nil {
				for _, record := range ts.Records {
					templates.AddTemplate(f.Version, f.PacketNFv9.SourceId, record)
				}
			}
			nfTemplateFSidx++
		} else if f.fsheader.Id == nfv9OptionsTemplateFlowSetID {
			f.buf.Reset()
			f.buf.Write(payload.Next(nextrelpos))

			f.PacketNFv9.NFv9OptionsTemplateFS = f.PacketNFv9.NFv9OptionsTemplateFS[:cap(f.PacketNFv9.NFv9OptionsTemplateFS)]
			if nfOptsTemplateFSidx >= len(f.PacketNFv9.NFv9OptionsTemplateFS) {
				f.PacketNFv9.NFv9OptionsTemplateFS = append(f.PacketNFv9.NFv9OptionsTemplateFS, NFv9OptionsTemplateFlowSet{})
			}

			ts := &f.PacketNFv9.NFv9OptionsTemplateFS[nfOptsTemplateFSidx]

			ts.FlowSetHeader = f.fsheader
			if err := DecodeNFv9OptionsTemplateSet(f.buf, ts); err != nil {
				return fmt.Errorf("decode ipfix packet: %v", err)
			}

			if templates != nil {
				for _, record := range ts.Records {
					templates.AddTemplate(f.Version, f.PacketNFv9.SourceId, record)
				}
			}
			nfOptsTemplateFSidx++
		} else if f.fsheader.Id >= dataTemplateFlowSetID {
			f.buf.Reset()
			f.buf.Write(payload.Next(nextrelpos))

			if templates == nil {
				continue
			}

			template, err := templates.GetTemplate(f.Version, f.PacketNFv9.SourceId, f.fsheader.Id)
			if err != nil {
				return err
			}

			switch templatec := template.(type) {
			case TemplateRecord:
				f.PacketNFv9.DataFS = f.PacketNFv9.DataFS[:cap(f.PacketNFv9.DataFS)]

				if nfDataFSidx >= len(f.PacketNFv9.DataFS) {
					f.PacketNFv9.DataFS = append(f.PacketNFv9.DataFS, DataFlowSet{})
				}

				f.PacketNFv9.DataFS[nfDataFSidx].FlowSetHeader = f.fsheader
				if err := DecodeDataSet(f.buf, templatec.Fields, &f.PacketNFv9.DataFS[nfDataFSidx]); err != nil {
					return err
				}
				nfDataFSidx++
			case NFv9OptionsTemplateRecord:
				f.PacketNFv9.OptionsDataFS = f.PacketNFv9.OptionsDataFS[:cap(f.PacketNFv9.OptionsDataFS)]

				if nfOptsDataFSidx >= len(f.PacketNFv9.OptionsDataFS) {
					f.PacketNFv9.OptionsDataFS = append(f.PacketNFv9.OptionsDataFS, OptionsDataFlowSet{})
				}

				optFS := &f.PacketNFv9.OptionsDataFS[nfOptsDataFSidx]

				optFS.FlowSetHeader = f.fsheader
				if err := DecodeOptionsDataSet(f.buf, optFS, templatec.Scopes, templatec.Options); err != nil {
					return err
				}
				nfOptsDataFSidx++
			default:
				return fmt.Errorf("unknown record type: %T", templatec)
			}
		} else {
			return NewErrorFlowId(f.fsheader.Id)
		}
	}

	f.PacketNFv9.DataFS = f.PacketNFv9.DataFS[:nfDataFSidx]
	f.PacketNFv9.TemplateFS = f.PacketNFv9.TemplateFS[:nfTemplateFSidx]
	f.PacketNFv9.NFv9OptionsTemplateFS = f.PacketNFv9.NFv9OptionsTemplateFS[:nfOptsTemplateFSidx]
	f.PacketNFv9.OptionsDataFS = f.PacketNFv9.OptionsDataFS[:nfOptsDataFSidx]

	return nil
}

// DecodeIPFIXPacket decodes and collects the message in ipfix protocol format.
func (f *FlowMessage) DecodeIPFIXPacket(payload *bytes.Buffer, templates NetFlowTemplateSystem) error {
	var (
		ipxDataFSidx, ipxTemplateFSidx, ipxOptsTemplateFSidx, ipxOptsDataFSidx int
	)

	for i := 0; i < int(f.PacketIPFIX.Length) && payload.Len() > 0; i++ {
		if ok := f.fsheader.ReadFrom(payload); !ok {
			return NewErrorDecodingNetFlow("error decoding packet: invalid FlowSet header.")
		}

		nextrelpos := int(f.fsheader.Length) - flowSetHeaderSize
		if nextrelpos < 0 {
			return NewErrorDecodingNetFlow("error decoding packet: non-terminated stream.")
		}

		if f.fsheader.Id == ipfixTemplateFlowSetID {
			f.buf.Reset()
			f.buf.Write(payload.Next(nextrelpos))

			f.PacketIPFIX.TemplateFS = f.PacketIPFIX.TemplateFS[:cap(f.PacketIPFIX.TemplateFS)]
			if ipxTemplateFSidx >= len(f.PacketIPFIX.TemplateFS) {
				f.PacketIPFIX.TemplateFS = append(f.PacketIPFIX.TemplateFS, TemplateFlowSet{})
			}

			ts := &f.PacketIPFIX.TemplateFS[ipxTemplateFSidx]
			if err := DecodeTemplateSet(f.buf, ts); err != nil {
				return err
			}

			ts.FlowSetHeader = f.fsheader
			if templates != nil {
				for _, record := range ts.Records {
					templates.AddTemplate(f.Version, f.PacketIPFIX.ObservationDomainId, record)
				}
			}
			ipxTemplateFSidx++
		} else if f.fsheader.Id == ipfixOptionsTemplateFlowSetID {
			f.buf.Reset()
			f.buf.Write(payload.Next(nextrelpos))

			f.PacketIPFIX.IPFIXOptionsTemplateFS = f.PacketIPFIX.IPFIXOptionsTemplateFS[:cap(f.PacketIPFIX.IPFIXOptionsTemplateFS)]

			if ipxOptsTemplateFSidx >= len(f.PacketIPFIX.IPFIXOptionsTemplateFS) {
				f.PacketIPFIX.IPFIXOptionsTemplateFS = append(f.PacketIPFIX.IPFIXOptionsTemplateFS, IPFIXOptionsTemplateFlowSet{})
			}

			opt := &f.PacketIPFIX.IPFIXOptionsTemplateFS[ipxOptsTemplateFSidx]

			opt.FlowSetHeader = f.fsheader
			if err := DecodeIPFIXOptionsTemplateSet(f.buf, opt); err != nil {
				return err
			}

			if templates != nil {
				for _, record := range opt.Records {
					templates.AddTemplate(f.Version, f.PacketIPFIX.ObservationDomainId, record)
				}
			}
			ipxOptsTemplateFSidx++
		} else if f.fsheader.Id >= dataTemplateFlowSetID {
			f.buf.Reset()
			f.buf.Write(payload.Next(nextrelpos))

			if templates == nil {
				continue
			}

			template, err := templates.GetTemplate(f.Version, f.PacketIPFIX.ObservationDomainId, f.fsheader.Id)
			if err != nil {
				return err
			}

			switch templatec := template.(type) {
			case TemplateRecord:
				f.PacketIPFIX.DataFS = f.PacketIPFIX.DataFS[:cap(f.PacketIPFIX.DataFS)]

				if ipxDataFSidx >= len(f.PacketIPFIX.DataFS) {
					f.PacketIPFIX.DataFS = append(f.PacketIPFIX.DataFS, DataFlowSet{})
				}

				f.PacketIPFIX.DataFS[ipxDataFSidx].FlowSetHeader = f.fsheader
				if err := DecodeDataSet(f.buf, templatec.Fields, &f.PacketIPFIX.DataFS[ipxDataFSidx]); err != nil {
					return err
				}
				ipxDataFSidx++
			case IPFIXOptionsTemplateRecord:
				f.PacketIPFIX.OptionsDataFS = f.PacketIPFIX.OptionsDataFS[:cap(f.PacketIPFIX.OptionsDataFS)]

				if ipxOptsDataFSidx >= len(f.PacketIPFIX.OptionsDataFS) {
					f.PacketIPFIX.OptionsDataFS = append(f.PacketIPFIX.OptionsDataFS, OptionsDataFlowSet{})
				}

				optFS := &f.PacketIPFIX.OptionsDataFS[ipxOptsDataFSidx]

				optFS.FlowSetHeader = f.fsheader
				if err := DecodeOptionsDataSet(f.buf, optFS, templatec.Scopes, templatec.Options); err != nil {
					return err
				}
				ipxOptsDataFSidx++
			default:
				return fmt.Errorf("unknown record type: %T", templatec)
			}
		} else {
			return NewErrorFlowId(f.fsheader.Id)
		}
	}

	f.PacketIPFIX.DataFS = f.PacketIPFIX.DataFS[:ipxDataFSidx]
	f.PacketIPFIX.TemplateFS = f.PacketIPFIX.TemplateFS[:ipxTemplateFSidx]
	f.PacketIPFIX.IPFIXOptionsTemplateFS = f.PacketIPFIX.IPFIXOptionsTemplateFS[:ipxOptsTemplateFSidx]
	f.PacketIPFIX.OptionsDataFS = f.PacketIPFIX.OptionsDataFS[:ipxOptsDataFSidx]

	return nil
}
