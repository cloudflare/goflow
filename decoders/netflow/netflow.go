package netflow

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/goflow/decoders/utils"
	"sync"
)

type FlowBaseTemplateSet map[uint16]map[uint32]map[uint16]interface{}

type NetFlowTemplateSystem interface {
	GetTemplate(version uint16, obsDomainId uint32, templateId uint16) (interface{}, error)
	AddTemplate(version uint16, obsDomainId uint32, template interface{})
}

func DecodeNFv9OptionsTemplateSet(payload *bytes.Buffer) ([]NFv9OptionsTemplateRecord, error) {
	records := make([]NFv9OptionsTemplateRecord, 0)
	var err error
	for payload.Len() >= 4 {
		optsTemplateRecord := NFv9OptionsTemplateRecord{}
		err = utils.BinaryDecoder(payload, &optsTemplateRecord.TemplateId, &optsTemplateRecord.ScopeLength, &optsTemplateRecord.OptionLength)
		if err != nil {
			break
		}

		sizeScope := int(optsTemplateRecord.ScopeLength) / 4
		sizeOptions := int(optsTemplateRecord.OptionLength) / 4
		if sizeScope < 0 || sizeOptions < 0 {
			return records, NewErrorDecodingNetFlow("Error decoding OptionsTemplateSet: negative length.")
		}

		fields := make([]Field, sizeScope)
		for i := 0; i < sizeScope; i++ {
			field := Field{}
			err = utils.BinaryDecoder(payload, &field)
			fields[i] = field
		}
		optsTemplateRecord.Scopes = fields

		fields = make([]Field, sizeOptions)
		for i := 0; i < sizeOptions; i++ {
			field := Field{}
			err = utils.BinaryDecoder(payload, &field)
			fields[i] = field
		}
		optsTemplateRecord.Options = fields

		records = append(records, optsTemplateRecord)
	}

	return records, nil
}

func DecodeIPFIXOptionsTemplateSet(payload *bytes.Buffer) ([]IPFIXOptionsTemplateRecord, error) {
	records := make([]IPFIXOptionsTemplateRecord, 0)
	var err error
	for payload.Len() >= 4 {
		optsTemplateRecord := IPFIXOptionsTemplateRecord{}
		err = utils.BinaryDecoder(payload, &optsTemplateRecord.TemplateId, &optsTemplateRecord.FieldCount, &optsTemplateRecord.ScopeFieldCount)
		if err != nil {
			break
		}

		fields := make([]Field, int(optsTemplateRecord.ScopeFieldCount))
		for i := 0; i < int(optsTemplateRecord.ScopeFieldCount); i++ {
			field := Field{}
			err = utils.BinaryDecoder(payload, &field)
			fields[i] = field
		}
		optsTemplateRecord.Scopes = fields

		optionsSize := int(optsTemplateRecord.FieldCount) - int(optsTemplateRecord.ScopeFieldCount)
		if optionsSize < 0 {
			return records, NewErrorDecodingNetFlow("Error decoding OptionsTemplateSet: negative length.")
		}
		fields = make([]Field, optionsSize)
		for i := 0; i < optionsSize; i++ {
			field := Field{}
			err = utils.BinaryDecoder(payload, &field)
			fields[i] = field
		}
		optsTemplateRecord.Options = fields

		records = append(records, optsTemplateRecord)
	}

	return records, nil
}

func DecodeTemplateSet(payload *bytes.Buffer) ([]TemplateRecord, error) {
	records := make([]TemplateRecord, 0)
	var err error
	for payload.Len() >= 4 {
		templateRecord := TemplateRecord{}
		err = utils.BinaryDecoder(payload, &templateRecord.TemplateId, &templateRecord.FieldCount)
		if err != nil {
			break
		}

		if int(templateRecord.FieldCount) < 0 {
			return records, NewErrorDecodingNetFlow("Error decoding TemplateSet: zero count.")
		}

		fields := make([]Field, int(templateRecord.FieldCount))
		for i := 0; i < int(templateRecord.FieldCount); i++ {
			field := Field{}
			err = utils.BinaryDecoder(payload, &field)
			fields[i] = field
		}
		templateRecord.Fields = fields
		records = append(records, templateRecord)
	}

	return records, nil
}

func GetTemplateSize(template []Field) int {
	sum := 0
	for _, templateField := range template {
		sum += int(templateField.Length)
	}
	return sum
}

func DecodeDataSetUsingFields(payload *bytes.Buffer, listFields []Field) []DataField {
	for payload.Len() >= GetTemplateSize(listFields) {

		dataFields := make([]DataField, len(listFields))

		for i, templateField := range listFields {
			value := payload.Next(int(templateField.Length))
			nfvalue := DataField{
				Type:  templateField.Type,
				Value: value,
			}
			dataFields[i] = nfvalue
		}
		return dataFields
	}
	return []DataField{}
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
	return fmt.Sprintf("No %v template %v found for and domain id %v", e.typeTemplate, e.templateId, e.obsDomainId)
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
	return fmt.Sprintf("Unknown NetFlow version %v (only decodes v9 and v10/IPFIX)", e.version)
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
	return fmt.Sprintf("Unknown flow id %v (templates < 256, data >= 256)", e.id)
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
	return fmt.Sprintf("Error decoding NetFlow: %v", e.msg)
}

func DecodeOptionsDataSet(payload *bytes.Buffer, listFieldsScopes, listFieldsOption []Field) ([]OptionsDataRecord, error) {
	records := make([]OptionsDataRecord, 0)

	listFieldsScopesSize := GetTemplateSize(listFieldsScopes)
	listFieldsOptionSize := GetTemplateSize(listFieldsOption)

	for payload.Len() >= listFieldsScopesSize+listFieldsOptionSize {
		payloadLim := bytes.NewBuffer(payload.Next(listFieldsScopesSize))
		scopeValues := DecodeDataSetUsingFields(payloadLim, listFieldsScopes)
		payloadLim = bytes.NewBuffer(payload.Next(listFieldsOptionSize))
		optionValues := DecodeDataSetUsingFields(payloadLim, listFieldsOption)

		record := OptionsDataRecord{
			ScopesValues:  scopeValues,
			OptionsValues: optionValues,
		}

		records = append(records, record)
	}
	return records, nil
}

func DecodeDataSet(payload *bytes.Buffer, listFields []Field) ([]DataRecord, error) {
	records := make([]DataRecord, 0)

	listFieldsSize := GetTemplateSize(listFields)
	for payload.Len() >= listFieldsSize {
		payloadLim := bytes.NewBuffer(payload.Next(listFieldsSize))
		values := DecodeDataSetUsingFields(payloadLim, listFields)

		record := DataRecord{
			Values: values,
		}

		records = append(records, record)
	}
	return records, nil
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
	if exists != true {
		ts.templates[version] = make(map[uint32]map[uint16]interface{})
	}
	_, exists = ts.templates[version][obsDomainId]
	if exists != true {
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

func DecodeMessage(payload *bytes.Buffer, templates NetFlowTemplateSystem) (interface{}, error) {
	var size uint16
	packetNFv9 := NFv9Packet{}
	packetIPFIX := IPFIXPacket{}
	var returnItem interface{}

	var version uint16
	var obsDomainId uint32
	binary.Read(payload, binary.BigEndian, &version)

	if version == 9 {
		utils.BinaryDecoder(payload, &packetNFv9.Count, &packetNFv9.SystemUptime, &packetNFv9.UnixSeconds, &packetNFv9.SequenceNumber, &packetNFv9.SourceId)
		size = packetNFv9.Count
		packetNFv9.Version = version
		returnItem = *(&packetNFv9)
		obsDomainId = packetNFv9.SourceId
	} else if version == 10 {
		utils.BinaryDecoder(payload, &packetIPFIX.Length, &packetIPFIX.ExportTime, &packetIPFIX.SequenceNumber, &packetIPFIX.ObservationDomainId)
		size = packetIPFIX.Length
		packetIPFIX.Version = version
		returnItem = *(&packetIPFIX)
		obsDomainId = packetIPFIX.ObservationDomainId
	} else {
		return nil, NewErrorVersion(version)
	}

	for i := 0; ((i < int(size) && version == 9) || version == 10) && payload.Len() > 0; i++ {
		fsheader := FlowSetHeader{}
		utils.BinaryDecoder(payload, &fsheader)

		nextrelpos := int(fsheader.Length) - binary.Size(fsheader)
		if nextrelpos < 0 {
			return returnItem, NewErrorDecodingNetFlow("Error decoding packet: non-terminated stream.")
		}

		var flowSet interface{}

		if fsheader.Id == 0 && version == 9 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeTemplateSet(templateReader)
			if err != nil {
				return returnItem, err
			}
			templatefs := TemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}

			flowSet = templatefs

			if templates != nil {
				for _, record := range records {
					templates.AddTemplate(version, obsDomainId, record)
				}
			}

		} else if fsheader.Id == 1 && version == 9 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeNFv9OptionsTemplateSet(templateReader)
			if err != nil {
				return returnItem, err
			}
			optsTemplatefs := NFv9OptionsTemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}
			flowSet = optsTemplatefs

			if templates != nil {
				for _, record := range records {
					templates.AddTemplate(version, obsDomainId, record)
				}
			}

		} else if fsheader.Id == 2 && version == 10 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeTemplateSet(templateReader)
			if err != nil {
				return returnItem, err
			}
			templatefs := TemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}
			flowSet = templatefs

			if templates != nil {
				for _, record := range records {
					templates.AddTemplate(version, obsDomainId, record)
				}
			}

		} else if fsheader.Id == 3 && version == 10 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeIPFIXOptionsTemplateSet(templateReader)
			if err != nil {
				return returnItem, err
			}
			optsTemplatefs := IPFIXOptionsTemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}
			flowSet = optsTemplatefs

			if templates != nil {
				for _, record := range records {
					templates.AddTemplate(version, obsDomainId, record)
				}
			}

		} else if fsheader.Id >= 256 {
			dataReader := bytes.NewBuffer(payload.Next(nextrelpos))

			if templates == nil {
				continue
			}

			template, err := templates.GetTemplate(version, obsDomainId, fsheader.Id)

			if err == nil {
				switch templatec := template.(type) {
				case TemplateRecord:
					records, err := DecodeDataSet(dataReader, templatec.Fields)
					if err != nil {
						return returnItem, err
					}
					datafs := DataFlowSet{
						FlowSetHeader: fsheader,
						Records:       records,
					}
					flowSet = datafs
				case IPFIXOptionsTemplateRecord:
					records, err := DecodeOptionsDataSet(dataReader, templatec.Scopes, templatec.Options)
					if err != nil {
						return returnItem, err
					}

					datafs := OptionsDataFlowSet{
						FlowSetHeader: fsheader,
						Records:       records,
					}
					flowSet = datafs
				case NFv9OptionsTemplateRecord:
					records, err := DecodeOptionsDataSet(dataReader, templatec.Scopes, templatec.Options)
					if err != nil {
						return returnItem, err
					}

					datafs := OptionsDataFlowSet{
						FlowSetHeader: fsheader,
						Records:       records,
					}
					flowSet = datafs
				}
			} else {
				return returnItem, err
			}
		} else {
			return returnItem, NewErrorFlowId(fsheader.Id)
		}

		if version == 9 && flowSet != nil {
			packetNFv9.FlowSets = append(packetNFv9.FlowSets, flowSet)
		} else if version == 10 && flowSet != nil {
			packetIPFIX.FlowSets = append(packetIPFIX.FlowSets, flowSet)
		}
	}

	if version == 9 {
		return packetNFv9, nil
	} else if version == 10 {
		return packetIPFIX, nil
	} else {
		return returnItem, NewErrorVersion(version)
	}
}
