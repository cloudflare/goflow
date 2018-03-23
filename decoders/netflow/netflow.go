package netflow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cloudflare/goflow/decoders"
	"github.com/cloudflare/goflow/decoders/utils"
	"net"
	"strconv"
	"sync"
)

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte
}

type BaseMessageDecoded struct {
	Version uint16
	Src     net.IP
	Port    int
	Packet  decoder.MessageDecoded
}

type FlowBaseTemplateSet map[string]map[uint32]map[uint16][]Field
type FlowBaseOptionRecords struct {
	Scopes  []Field
	Options []Field
}
type FlowBaseOptionsTemplateSet map[string]map[uint32]map[uint16]FlowBaseOptionRecords
type FlowBaseTemplateInfo map[string]map[uint32]map[uint16]bool

type DecoderConfig struct {
	NetFlowV9TemplateSet        FlowBaseTemplateSet
	NetFlowV9OptionsTemplateSet FlowBaseOptionsTemplateSet
	NetFlowV9TemplateInfo       FlowBaseTemplateInfo

	IPFIXTemplateSet        FlowBaseTemplateSet
	IPFIXOptionsTemplateSet FlowBaseOptionsTemplateSet
	IPFIXTemplateInfo       FlowBaseTemplateInfo

	NetFlowV9TemplateSetLock *sync.RWMutex
	IPFIXTemplateSetLock     *sync.RWMutex

	AddTemplates    bool
	UniqueTemplates bool
}

func CreateConfig() DecoderConfig {
	config := DecoderConfig{
		AddTemplates:                true,
		UniqueTemplates:             true,
		NetFlowV9TemplateSetLock:    &sync.RWMutex{},
		IPFIXTemplateSetLock:        &sync.RWMutex{},
		NetFlowV9TemplateSet:        make(map[string]map[uint32]map[uint16][]Field),
		NetFlowV9OptionsTemplateSet: make(map[string]map[uint32]map[uint16]FlowBaseOptionRecords),
		NetFlowV9TemplateInfo:       make(map[string]map[uint32]map[uint16]bool),
		IPFIXTemplateSet:            make(map[string]map[uint32]map[uint16][]Field),
		IPFIXOptionsTemplateSet:     make(map[string]map[uint32]map[uint16]FlowBaseOptionRecords),
		IPFIXTemplateInfo:           make(map[string]map[uint32]map[uint16]bool),
	}
	return config
}

func DecodePacket(msg decoder.Message, config decoder.DecoderConfig) (decoder.MessageDecoded, error) {
	baseMsg := msg.(BaseMessage)
	payload := bytes.NewBuffer(baseMsg.Payload)
	configdec := config.(DecoderConfig)

	key := baseMsg.Src.String() + ":" + strconv.Itoa(baseMsg.Port)
	if configdec.UniqueTemplates {
		key = "unique"
	}

	version, msgDecoded, err := DecodeMessage(key, configdec.UniqueTemplates, payload, config)

	baseMsgDecoded := BaseMessageDecoded{
		Version: version,
		Src:     baseMsg.Src,
		Port:    baseMsg.Port,
		Packet:  msgDecoded,
	}

	return baseMsgDecoded, err
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
			return records, errors.New("Error decoding OptionsTemplateSet: negative length.")
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
			return records, errors.New("Error decoding OptionsTemplateSet: negative length.")
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
			return records, errors.New("Error decoding TemplateSet: zero count.")
		}

		fields := make([]Field, int(templateRecord.FieldCount))
		for i := 0; i < int(templateRecord.FieldCount); i++ {
			field := Field{}
			err = utils.BinaryDecoder(payload, &field)
			fields[i] = field
		}
		templateRecord.Fields = fields
		//fmt.Printf("  %v\n", templateRecord)
		records = append(records, templateRecord)
	}

	return records, nil
}

func AddTemplate(key string, obsDomainId uint32, templateRecords []TemplateRecord, listTemplates FlowBaseTemplateSet, listTemplatesInfo FlowBaseTemplateInfo) {
	for _, templateRecord := range templateRecords {
		_, exists := listTemplatesInfo[key]
		if exists != true {
			listTemplatesInfo[key] = make(map[uint32]map[uint16]bool)
		}
		_, exists = listTemplates[key]
		if exists != true {
			listTemplates[key] = make(map[uint32]map[uint16][]Field)
		}
		_, exists = listTemplatesInfo[key][obsDomainId]
		if exists != true {
			listTemplatesInfo[key][obsDomainId] = make(map[uint16]bool)
		}
		_, exists = listTemplates[key][obsDomainId]
		if exists != true {
			listTemplates[key][obsDomainId] = make(map[uint16][]Field)
		}
		listTemplates[key][obsDomainId][templateRecord.TemplateId] = templateRecord.Fields
		listTemplatesInfo[key][obsDomainId][templateRecord.TemplateId] = true
	}
}

func AddNFv9OptionsTemplate(key string, obsDomainId uint32, templateRecords []NFv9OptionsTemplateRecord, listOptionsTemplates FlowBaseOptionsTemplateSet, listTemplatesInfo FlowBaseTemplateInfo) {
	for _, templateRecord := range templateRecords {
		_, exists := listTemplatesInfo[key]
		if exists != true {
			listTemplatesInfo[key] = make(map[uint32]map[uint16]bool)
		}
		_, exists = listOptionsTemplates[key]
		if exists != true {
			listOptionsTemplates[key] = make(map[uint32]map[uint16]FlowBaseOptionRecords)
		}
		_, exists = listTemplatesInfo[key][obsDomainId]
		if exists != true {
			listTemplatesInfo[key][obsDomainId] = make(map[uint16]bool)
		}
		_, exists = listOptionsTemplates[key][obsDomainId]
		if exists != true {
			listOptionsTemplates[key][obsDomainId] = make(map[uint16]FlowBaseOptionRecords)
		}
		optionRecord := FlowBaseOptionRecords{
			Scopes:  templateRecord.Scopes,
			Options: templateRecord.Options,
		}
		listOptionsTemplates[key][obsDomainId][templateRecord.TemplateId] = optionRecord
		listTemplatesInfo[key][obsDomainId][templateRecord.TemplateId] = false
	}
}

func AddIPFIXOptionsTemplate(key string, obsDomainId uint32, templateRecords []IPFIXOptionsTemplateRecord, listOptionsTemplates FlowBaseOptionsTemplateSet, listTemplatesInfo FlowBaseTemplateInfo) {
	for _, templateRecord := range templateRecords {
		_, exists := listTemplatesInfo[key]
		if exists != true {
			listTemplatesInfo[key] = make(map[uint32]map[uint16]bool)
		}
		_, exists = listOptionsTemplates[key]
		if exists != true {
			listOptionsTemplates[key] = make(map[uint32]map[uint16]FlowBaseOptionRecords)
		}
		_, exists = listTemplatesInfo[key][obsDomainId]
		if exists != true {
			listTemplatesInfo[key][obsDomainId] = make(map[uint16]bool)
		}
		_, exists = listOptionsTemplates[key][obsDomainId]
		if exists != true {
			listOptionsTemplates[key][obsDomainId] = make(map[uint16]FlowBaseOptionRecords)
		}
		optionRecord := FlowBaseOptionRecords{
			Scopes:  templateRecord.Scopes,
			Options: templateRecord.Options,
		}
		listOptionsTemplates[key][obsDomainId][templateRecord.TemplateId] = optionRecord
		listTemplatesInfo[key][obsDomainId][templateRecord.TemplateId] = false
	}
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
	src          string
	obsDomainId  uint32
	templateId   uint16
	typeTemplate string
}

func NewErrorTemplateNotFound(src string, obsDomainId uint32, templateId uint16, typeTemplate string) *ErrorTemplateNotFound {
	return &ErrorTemplateNotFound{
		src:          src,
		obsDomainId:  obsDomainId,
		templateId:   templateId,
		typeTemplate: typeTemplate,
	}
}

func (e *ErrorTemplateNotFound) Error() string {
	return fmt.Sprintf("No %v template %v found for source %v and domain id %v", e.typeTemplate, e.templateId, e.src, e.obsDomainId)
}

func DecodeOptionsDataSet(src string, obsDomainId uint32, templateId uint16, payload *bytes.Buffer, listOptionsTemplates FlowBaseOptionsTemplateSet) ([]OptionsDataRecord, error) {
	records := make([]OptionsDataRecord, 0)

	listOptionsTemplatesSrc, oksrc := listOptionsTemplates[src]
	if oksrc {
		listOptionsTemplatesSrcObs, okobs := listOptionsTemplatesSrc[obsDomainId]
		if okobs {
			listOptionsFields, oktmp := listOptionsTemplatesSrcObs[templateId]
			if oktmp {
				listFieldsScopes := listOptionsFields.Scopes
				listFieldsOption := listOptionsFields.Options

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
			} else {
				return []OptionsDataRecord{}, NewErrorTemplateNotFound(src, obsDomainId, templateId, "options")
			}
		} else {
			return []OptionsDataRecord{}, NewErrorTemplateNotFound(src, obsDomainId, templateId, "options")
		}
	} else {
		return []OptionsDataRecord{}, NewErrorTemplateNotFound(src, obsDomainId, templateId, "options")
	}
}

func DecodeDataSet(src string, obsDomainId uint32, templateId uint16, payload *bytes.Buffer, listTemplates FlowBaseTemplateSet) ([]DataRecord, error) {
	records := make([]DataRecord, 0)

	listTemplatesSrc, oksrc := listTemplates[src]
	if oksrc {
		listTemplatesSrcObs, okobs := listTemplatesSrc[obsDomainId]
		if okobs {
			listFields, oktmp := listTemplatesSrcObs[templateId]
			if oktmp {
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
			} else {
				return []DataRecord{}, NewErrorTemplateNotFound(src, obsDomainId, templateId, "data")
			}
		} else {
			return []DataRecord{}, NewErrorTemplateNotFound(src, obsDomainId, templateId, "data")
		}
	} else {
		return []DataRecord{}, NewErrorTemplateNotFound(src, obsDomainId, templateId, "data")
	}
}

func IsDataSet(src string, obsDomainId uint32, templateId uint16, listTemplatesInfo FlowBaseTemplateInfo) (bool, error) {
	listTemplatesInfoSrc, oksrc := listTemplatesInfo[src]
	if oksrc {
		listTemplatesInfoSrcObs, okobs := listTemplatesInfoSrc[obsDomainId]
		if okobs {
			listBool, oktmp := listTemplatesInfoSrcObs[templateId]
			if oktmp {
				return listBool, nil
			}
			return false, NewErrorTemplateNotFound(src, obsDomainId, templateId, "info")
		}
		return false, NewErrorTemplateNotFound(src, obsDomainId, templateId, "info")
	}
	return false, NewErrorTemplateNotFound(src, obsDomainId, templateId, "info")
}

func DecodeMessage(key string, uniqueTemplates bool, payload *bytes.Buffer, config decoder.DecoderConfig) (uint16, decoder.MessageDecoded, error) {
	configdec := config.(DecoderConfig)

	var size uint16
	var templateLock *sync.RWMutex
	var confTemplateInfo *FlowBaseTemplateInfo
	var confOptionsTemplate *FlowBaseOptionsTemplateSet
	var confTemplate *FlowBaseTemplateSet
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
		templateLock = configdec.NetFlowV9TemplateSetLock
		confTemplateInfo = &configdec.NetFlowV9TemplateInfo
		confOptionsTemplate = &configdec.NetFlowV9OptionsTemplateSet
		confTemplate = &configdec.NetFlowV9TemplateSet
		returnItem = *(&packetNFv9)
		obsDomainId = packetNFv9.SourceId
	} else if version == 10 {
		utils.BinaryDecoder(payload, &packetIPFIX.Length, &packetIPFIX.ExportTime, &packetIPFIX.SequenceNumber, &packetIPFIX.ObservationDomainId)
		size = packetIPFIX.Length
		packetIPFIX.Version = version
		templateLock = configdec.IPFIXTemplateSetLock
		confTemplateInfo = &configdec.IPFIXTemplateInfo
		confOptionsTemplate = &configdec.IPFIXOptionsTemplateSet
		confTemplate = &configdec.IPFIXTemplateSet
		returnItem = *(&packetIPFIX)
		obsDomainId = packetIPFIX.ObservationDomainId
	} else {
		return version, nil, errors.New(fmt.Sprintf("Unknown version %v.", version))
	}

	if uniqueTemplates {
		obsDomainId = 0
	}

	for i := 0; ((i < int(size) && version == 9) || version == 10) && payload.Len() > 0; i++ {
		fsheader := FlowSetHeader{}
		utils.BinaryDecoder(payload, &fsheader)

		nextrelpos := int(fsheader.Length) - binary.Size(fsheader)
		if nextrelpos < 0 {
			return version, returnItem, errors.New("Error decoding packet: non-terminated stream.")
		}

		var flowSet interface{}

		if fsheader.Id == 0 && version == 9 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeTemplateSet(templateReader)
			if err != nil {
				return version, returnItem, err
			}
			templatefs := TemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}

			flowSet = templatefs

			if configdec.AddTemplates {
				templateLock.Lock()
				AddTemplate(key, obsDomainId, records, *confTemplate, *confTemplateInfo)
				templateLock.Unlock()
			}

		} else if fsheader.Id == 1 && version == 9 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeNFv9OptionsTemplateSet(templateReader)
			if err != nil {
				return version, returnItem, err
			}
			optsTemplatefs := NFv9OptionsTemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}
			flowSet = optsTemplatefs

			if configdec.AddTemplates {
				templateLock.Lock()
				AddNFv9OptionsTemplate(key, obsDomainId, records, *confOptionsTemplate, *confTemplateInfo)
				templateLock.Unlock()
			}

		} else if fsheader.Id == 2 && version == 10 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeTemplateSet(templateReader)
			if err != nil {
				return version, returnItem, err
			}
			templatefs := TemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}
			flowSet = templatefs

			if configdec.AddTemplates {
				templateLock.Lock()
				AddTemplate(key, obsDomainId, records, *confTemplate, *confTemplateInfo)
				templateLock.Unlock()
			}

		} else if fsheader.Id == 3 && version == 10 {
			templateReader := bytes.NewBuffer(payload.Next(nextrelpos))
			records, err := DecodeIPFIXOptionsTemplateSet(templateReader)
			if err != nil {
				return version, returnItem, err
			}
			optsTemplatefs := IPFIXOptionsTemplateFlowSet{
				FlowSetHeader: fsheader,
				Records:       records,
			}
			flowSet = optsTemplatefs

			if configdec.AddTemplates {
				templateLock.Lock()
				AddIPFIXOptionsTemplate(key, obsDomainId, records, *confOptionsTemplate, *confTemplateInfo)
				templateLock.Unlock()
			}

		} else if fsheader.Id >= 256 {
			dataReader := bytes.NewBuffer(payload.Next(nextrelpos))

			templateLock.RLock()
			isDs, err := IsDataSet(key, obsDomainId, fsheader.Id, *confTemplateInfo)
			templateLock.RUnlock()
			if err == nil {
				if isDs {
					templateLock.RLock()
					records, err := DecodeDataSet(key, obsDomainId, fsheader.Id, dataReader, *confTemplate)
					if err != nil {
						return version, returnItem, err
					}
					templateLock.RUnlock()
					datafs := DataFlowSet{
						FlowSetHeader: fsheader,
						Records:       records,
					}
					flowSet = datafs
				} else {
					templateLock.RLock()
					records, err := DecodeOptionsDataSet(key, obsDomainId, fsheader.Id, dataReader, *confOptionsTemplate)
					if err != nil {
						return version, returnItem, err
					}
					templateLock.RUnlock()

					datafs := OptionsDataFlowSet{
						FlowSetHeader: fsheader,
						Records:       records,
					}
					flowSet = datafs
				}
			} else {
				return version, returnItem, err
			}
		} else {
			return version, returnItem, errors.New(fmt.Sprintf("%v not a valid Id\n", fsheader.Id))
		}

		if version == 9 && flowSet != nil {
			packetNFv9.FlowSets = append(packetNFv9.FlowSets, flowSet)
		} else if version == 10 && flowSet != nil {
			packetIPFIX.FlowSets = append(packetIPFIX.FlowSets, flowSet)
		}
	}

	if version == 9 {
		return version, packetNFv9, nil
	} else if version == 10 {
		return version, packetIPFIX, nil
	} else {
		return 0, returnItem, errors.New(fmt.Sprintf("Unknown version %v.", version))
	}
}

func CreateProcessor(numWorkers int, decoderConfig DecoderConfig, doneCallback decoder.DoneCallback, callbackArgs decoder.CallbackArgs, errorCallback decoder.ErrorCallback) decoder.Processor {

	decoderParams := decoder.DecoderParams{
		DecoderFunc:   DecodePacket,
		DecoderConfig: decoderConfig,
		DoneCallback:  doneCallback,
		CallbackArgs:  callbackArgs,
		ErrorCallback: errorCallback,
	}
	processor := decoder.CreateProcessor(numWorkers, decoderParams, "NetFlow")

	return processor
}
