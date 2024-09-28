package netflow

import (
	"bytes"
	"fmt"

	"github.com/cloudflare/goflow/v3/decoders/utils"
)

const (
	netflow                       = 9
	ipfix                         = 10
	nfv9TemplateFlowSetID         = 0
	nfv9OptionsTemplateFlowSetID  = 1
	ipfixTemplateFlowSetID        = 2
	ipfixOptionsTemplateFlowSetID = 3
	dataTemplateFlowSetID         = 256

	flowSetHeaderSize = 4
)

// FlowSets is a wrapper that contains different types of FlowSets that must be
// parsed and interpreted by the collector device.
type FlowSets struct {
	TemplateFS             []TemplateFlowSet
	DataFS                 []DataFlowSet
	OptionsDataFS          []OptionsDataFlowSet
	NFv9OptionsTemplateFS  []NFv9OptionsTemplateFlowSet
	IPFIXOptionsTemplateFS []IPFIXOptionsTemplateFlowSet
}

// FlowSetHeader contains fields shared by all Flow Sets (DataFlowSet,
// TemplateFlowSet, OptionsTemplateFlowSet).
type FlowSetHeader struct {
	// FlowSet ID:
	//    0 for TemplateFlowSet
	//    1 for OptionsTemplateFlowSet
	//    256-65535 for DataFlowSet (used as TemplateId)
	Id uint16

	// The total length of this FlowSet in bytes (including padding).
	Length uint16
}

// TemplateFlowSet is a collection of templates that describe structure of Data
// Records (actual NetFlow data).
type TemplateFlowSet struct {
	FlowSetHeader

	// List of Template Records
	Records []TemplateRecord
}

// DataFlowSet is a collection of Data Records (actual NetFlow data) and Options
// Data Records (meta data).
type DataFlowSet struct {
	FlowSetHeader

	// List of Data Records
	Records []DataRecord
}

// OptionsDataFlowSet is a collection of Options Data Records.
type OptionsDataFlowSet struct {
	FlowSetHeader

	// List of Options Data Records
	Records []OptionsDataRecord
}

// TemplateRecord is a single template that describes structure of a Flow Record
// (actual Netflow data).
type TemplateRecord struct {
	// Each of the newly generated Template Records is given a unique
	// Template ID. This uniqueness is local to the Observation Domain that
	// generated the Template ID. Template IDs of Data FlowSets are numbered
	// from 256 to 65535.
	TemplateId uint16

	// Number of fields in this Template Record. Because a Template FlowSet
	// usually contains multiple Template Records, this field allows the
	// Collector to determine the end of the current Template Record and
	// the start of the next.
	FieldCount uint16

	// List of fields in this Template Record.
	Fields []Field
}

// DataRecord is is a collection of field values.
// The type and length of the fields have been previously defined in the
// template record referenced by the FlowSet ID/template ID.
type DataRecord struct {
	// List of fields in this Data Record.
	Values []DataField
}

// OptionsDataRecord is meta data sent alongide actual NetFlow data. Combined
// with OptionsTemplateRecord it can be decoded to a single data row.
type OptionsDataRecord struct {
	// List of Scope values stored in raw format as []byte
	ScopesValues []DataField

	// List of Optons values stored in raw format as []byte
	OptionsValues []DataField
}

// Field describes type and length of a single value in a Flow Data Record.
// Field does not contain the record value itself it is just a description of
// what record value will look like.
type Field struct {
	// A numeric value that represents the type of field.
	Type uint16

	// The length (in bytes) of the field.
	Length uint16

	// IANA private enterprise number (PEN) of the authority defining the
	// Information Element identifier in this Template Record.
	//
	// Note: it's valid only for v10(IPFIX).
	EnterpriseNumber uint32
}

// IsVariableLength reports whether the Field is variable-length Information
// Element (RFC 7011 sec. 3.2. Field Specifier Format).
func (f *Field) IsVariableLength() bool {
	return f.Length == 0xffff
}

// ContainsEnterpriseNumber reports whether the Field is an enterprise-specific
// Information Element (RFC 7011 sec. 3.2. Field Specifier Format).
func (f *Field) ContainsEnterpriseNumber() bool {
	return f.Type&0x8000 != 0
}

// DataField contains the type and record value itself.
type DataField struct {
	// A numeric value that represents the type of field.
	Type uint16

	// The value (in bytes) of the field.
	Value []byte
}

// ReadFrom reads into receiver's fields Uint values from buffer and returns
// boolean flag telling if it was a success.
//
// Value is treated as big endian.
func (f *FlowSetHeader) ReadFrom(b *bytes.Buffer) bool {
	if ok := utils.ReadUint16FromBuffer(b, &f.Id); !ok {
		return false
	}
	if ok := utils.ReadUint16FromBuffer(b, &f.Length); !ok {
		return false
	}
	return true
}

// ReadFrom reads into receiver's fields Uint values from buffer and returns
// boolean flag telling if it was a success.
//
// Value is treated as big endian.
func (t *TemplateRecord) ReadFrom(b *bytes.Buffer) bool {
	if ok := utils.ReadUint16FromBuffer(b, &t.TemplateId); !ok {
		return false
	}
	if ok := utils.ReadUint16FromBuffer(b, &t.FieldCount); !ok {
		return false
	}
	return true
}

// ReadFrom reads into receiver's fields Uint values from buffer and returns
// boolean flag telling if it was a success.
//
// Value is treated as big endian.
func (f *Field) ReadFrom(b *bytes.Buffer) bool {
	if ok := utils.ReadUint16FromBuffer(b, &f.Type); !ok {
		return false
	}

	if ok := utils.ReadUint16FromBuffer(b, &f.Length); !ok {
		return false
	}

	if f.ContainsEnterpriseNumber() {
		if ok := utils.ReadUint32FromBuffer(b, &f.EnterpriseNumber); !ok {
			return false
		}
	}

	return true
}

func (flowSet OptionsDataFlowSet) String(TypeToString func(uint16) string, ScopeToString func(uint16) string) string {
	str := fmt.Sprintf("       Id %v\n", flowSet.Id)
	str += fmt.Sprintf("       Length: %v\n", flowSet.Length)
	str += fmt.Sprintf("       Records (%v records):\n", len(flowSet.Records))

	for j, record := range flowSet.Records {
		str += fmt.Sprintf("       - Record %v:\n", j)
		str += fmt.Sprintf("            Scopes (%v):\n", len(record.ScopesValues))

		for k, value := range record.ScopesValues {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, ScopeToString(value.Type), value.Type, value.Value)
		}

		str += fmt.Sprintf("            Options (%v):\n", len(record.OptionsValues))

		for k, value := range record.OptionsValues {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, TypeToString(value.Type), value.Type, value.Value)
		}
	}

	return str
}

func (flowSet DataFlowSet) String(TypeToString func(uint16) string) string {
	str := fmt.Sprintf("       Id %v\n", flowSet.Id)
	str += fmt.Sprintf("       Length: %v\n", flowSet.Length)
	str += fmt.Sprintf("       Records (%v records):\n", len(flowSet.Records))

	for j, record := range flowSet.Records {
		str += fmt.Sprintf("       - Record %v:\n", j)
		str += fmt.Sprintf("            Values (%v):\n", len(record.Values))

		for k, value := range record.Values {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, TypeToString(value.Type), value.Type, value.Value)
		}
	}

	return str
}

func (flowSet TemplateFlowSet) String(TypeToString func(uint16) string) string {
	str := fmt.Sprintf("       Id %v\n", flowSet.Id)
	str += fmt.Sprintf("       Length: %v\n", flowSet.Length)
	str += fmt.Sprintf("       Records (%v records):\n", len(flowSet.Records))

	for j, record := range flowSet.Records {
		str += fmt.Sprintf("       - %v. Record:\n", j)
		str += fmt.Sprintf("            TemplateId: %v\n", record.TemplateId)
		str += fmt.Sprintf("            FieldCount: %v\n", record.FieldCount)
		str += fmt.Sprintf("            Fields (%v):\n", len(record.Fields))

		for k, field := range record.Fields {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, TypeToString(field.Type), field.Type, field.Length)
		}
	}

	return str
}
