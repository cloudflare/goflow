package netflow

import (
	"fmt"
	"time"
)

const (
	NFV9_FIELD_IN_BYTES                     = 1
	NFV9_FIELD_IN_PKTS                      = 2
	NFV9_FIELD_FLOWS                        = 3
	NFV9_FIELD_PROTOCOL                     = 4
	NFV9_FIELD_SRC_TOS                      = 5
	NFV9_FIELD_TCP_FLAGS                    = 6
	NFV9_FIELD_L4_SRC_PORT                  = 7
	NFV9_FIELD_IPV4_SRC_ADDR                = 8
	NFV9_FIELD_SRC_MASK                     = 9
	NFV9_FIELD_INPUT_SNMP                   = 10
	NFV9_FIELD_L4_DST_PORT                  = 11
	NFV9_FIELD_IPV4_DST_ADDR                = 12
	NFV9_FIELD_DST_MASK                     = 13
	NFV9_FIELD_OUTPUT_SNMP                  = 14
	NFV9_FIELD_IPV4_NEXT_HOP                = 15
	NFV9_FIELD_SRC_AS                       = 16
	NFV9_FIELD_DST_AS                       = 17
	NFV9_FIELD_BGP_IPV4_NEXT_HOP            = 18
	NFV9_FIELD_MUL_DST_PKTS                 = 19
	NFV9_FIELD_MUL_DST_BYTES                = 20
	NFV9_FIELD_LAST_SWITCHED                = 21
	NFV9_FIELD_FIRST_SWITCHED               = 22
	NFV9_FIELD_OUT_BYTES                    = 23
	NFV9_FIELD_OUT_PKTS                     = 24
	NFV9_FIELD_MIN_PKT_LNGTH                = 25
	NFV9_FIELD_MAX_PKT_LNGTH                = 26
	NFV9_FIELD_IPV6_SRC_ADDR                = 27
	NFV9_FIELD_IPV6_DST_ADDR                = 28
	NFV9_FIELD_IPV6_SRC_MASK                = 29
	NFV9_FIELD_IPV6_DST_MASK                = 30
	NFV9_FIELD_IPV6_FLOW_LABEL              = 31
	NFV9_FIELD_ICMP_TYPE                    = 32
	NFV9_FIELD_MUL_IGMP_TYPE                = 33
	NFV9_FIELD_SAMPLING_INTERVAL            = 34
	NFV9_FIELD_SAMPLING_ALGORITHM           = 35
	NFV9_FIELD_FLOW_ACTIVE_TIMEOUT          = 36
	NFV9_FIELD_FLOW_INACTIVE_TIMEOUT        = 37
	NFV9_FIELD_ENGINE_TYPE                  = 38
	NFV9_FIELD_ENGINE_ID                    = 39
	NFV9_FIELD_TOTAL_BYTES_EXP              = 40
	NFV9_FIELD_TOTAL_PKTS_EXP               = 41
	NFV9_FIELD_TOTAL_FLOWS_EXP              = 42
	NFV9_FIELD_IPV4_SRC_PREFIX              = 44
	NFV9_FIELD_IPV4_DST_PREFIX              = 45
	NFV9_FIELD_MPLS_TOP_LABEL_TYPE          = 46
	NFV9_FIELD_MPLS_TOP_LABEL_IP_ADDR       = 47
	NFV9_FIELD_FLOW_SAMPLER_ID              = 48
	NFV9_FIELD_FLOW_SAMPLER_MODE            = 49
	NFV9_FIELD_FLOW_SAMPLER_RANDOM_INTERVAL = 50
	NFV9_FIELD_MIN_TTL                      = 52
	NFV9_FIELD_MAX_TTL                      = 53
	NFV9_FIELD_IPV4_IDENT                   = 54
	NFV9_FIELD_DST_TOS                      = 55
	NFV9_FIELD_IN_SRC_MAC                   = 56
	NFV9_FIELD_OUT_DST_MAC                  = 57
	NFV9_FIELD_SRC_VLAN                     = 58
	NFV9_FIELD_DST_VLAN                     = 59
	NFV9_FIELD_IP_PROTOCOL_VERSION          = 60
	NFV9_FIELD_DIRECTION                    = 61
	NFV9_FIELD_IPV6_NEXT_HOP                = 62
	NFV9_FIELD_BGP_IPV6_NEXT_HOP            = 63
	NFV9_FIELD_IPV6_OPTION_HEADERS          = 64
	NFV9_FIELD_MPLS_LABEL_1                 = 70
	NFV9_FIELD_MPLS_LABEL_2                 = 71
	NFV9_FIELD_MPLS_LABEL_3                 = 72
	NFV9_FIELD_MPLS_LABEL_4                 = 73
	NFV9_FIELD_MPLS_LABEL_5                 = 74
	NFV9_FIELD_MPLS_LABEL_6                 = 75
	NFV9_FIELD_MPLS_LABEL_7                 = 76
	NFV9_FIELD_MPLS_LABEL_8                 = 77
	NFV9_FIELD_MPLS_LABEL_9                 = 78
	NFV9_FIELD_MPLS_LABEL_10                = 79
	NFV9_FIELD_IN_DST_MAC                   = 80
	NFV9_FIELD_OUT_SRC_MAC                  = 81
	NFV9_FIELD_IF_NAME                      = 82
	NFV9_FIELD_IF_DESC                      = 83
	NFV9_FIELD_SAMPLER_NAME                 = 84
	NFV9_FIELD_IN_PERMANENT_BYTES           = 85
	NFV9_FIELD_IN_PERMANENT_PKTS            = 86
	NFV9_FIELD_FRAGMENT_OFFSET              = 88
	NFV9_FIELD_FORWARDING_STATUS            = 89
	NFV9_FIELD_MPLS_PAL_RD                  = 90
	NFV9_FIELD_MPLS_PREFIX_LEN              = 91
	NFV9_FIELD_SRC_TRAFFIC_INDEX            = 92
	NFV9_FIELD_DST_TRAFFIC_INDEX            = 93
	NFV9_FIELD_APPLICATION_DESCRIPTION      = 94
	NFV9_FIELD_APPLICATION_TAG              = 95
	NFV9_FIELD_APPLICATION_NAME             = 96
	NFV9_FIELD_postipDiffServCodePoint      = 98
	NFV9_FIELD_replication_factor           = 99
	NFV9_FIELD_layer2packetSectionOffset    = 102
	NFV9_FIELD_layer2packetSectionSize      = 103
	NFV9_FIELD_layer2packetSectionData      = 104
)

type NFv9Packet struct {
	Version        uint16
	Count          uint16
	SystemUptime   uint32
	UnixSeconds    uint32
	SequenceNumber uint32
	SourceId       uint32
	FlowSets       []interface{}
}

type NFv9OptionsTemplateFlowSet struct {
	FlowSetHeader
	Records []NFv9OptionsTemplateRecord
}

type NFv9OptionsTemplateRecord struct {
	TemplateId   uint16
	ScopeLength  uint16
	OptionLength uint16
	Scopes       []Field
	Options      []Field
}

func NFv9TypeToString(typeId uint16) string {

	nameList := map[uint16]string{
		1:   "IN_BYTES",
		2:   "IN_PKTS",
		3:   "FLOWS",
		4:   "PROTOCOL",
		5:   "SRC_TOS",
		6:   "TCP_FLAGS",
		7:   "L4_SRC_PORT",
		8:   "IPV4_SRC_ADDR",
		9:   "SRC_MASK",
		10:  "INPUT_SNMP",
		11:  "L4_DST_PORT",
		12:  "IPV4_DST_ADDR",
		13:  "DST_MASK",
		14:  "OUTPUT_SNMP",
		15:  "IPV4_NEXT_HOP",
		16:  "SRC_AS",
		17:  "DST_AS",
		18:  "BGP_IPV4_NEXT_HOP",
		19:  "MUL_DST_PKTS",
		20:  "MUL_DST_BYTES",
		21:  "LAST_SWITCHED",
		22:  "FIRST_SWITCHED",
		23:  "OUT_BYTES",
		24:  "OUT_PKTS",
		25:  "MIN_PKT_LNGTH",
		26:  "MAX_PKT_LNGTH",
		27:  "IPV6_SRC_ADDR",
		28:  "IPV6_DST_ADDR",
		29:  "IPV6_SRC_MASK",
		30:  "IPV6_DST_MASK",
		31:  "IPV6_FLOW_LABEL",
		32:  "ICMP_TYPE",
		33:  "MUL_IGMP_TYPE",
		34:  "SAMPLING_INTERVAL",
		35:  "SAMPLING_ALGORITHM",
		36:  "FLOW_ACTIVE_TIMEOUT",
		37:  "FLOW_INACTIVE_TIMEOUT",
		38:  "ENGINE_TYPE",
		39:  "ENGINE_ID",
		40:  "TOTAL_BYTES_EXP",
		41:  "TOTAL_PKTS_EXP",
		42:  "TOTAL_FLOWS_EXP",
		43:  "*Vendor Proprietary*",
		44:  "IPV4_SRC_PREFIX",
		45:  "IPV4_DST_PREFIX",
		46:  "MPLS_TOP_LABEL_TYPE",
		47:  "MPLS_TOP_LABEL_IP_ADDR",
		48:  "FLOW_SAMPLER_ID",
		49:  "FLOW_SAMPLER_MODE",
		50:  "FLOW_SAMPLER_RANDOM_INTERVAL",
		51:  "*Vendor Proprietary*",
		52:  "MIN_TTL",
		53:  "MAX_TTL",
		54:  "IPV4_IDENT",
		55:  "DST_TOS",
		56:  "IN_SRC_MAC",
		57:  "OUT_DST_MAC",
		58:  "SRC_VLAN",
		59:  "DST_VLAN",
		60:  "IP_PROTOCOL_VERSION",
		61:  "DIRECTION",
		62:  "IPV6_NEXT_HOP",
		63:  "BPG_IPV6_NEXT_HOP",
		64:  "IPV6_OPTION_HEADERS",
		65:  "*Vendor Proprietary*",
		66:  "*Vendor Proprietary*",
		67:  "*Vendor Proprietary*",
		68:  "*Vendor Proprietary*",
		69:  "*Vendor Proprietary*",
		70:  "MPLS_LABEL_1",
		71:  "MPLS_LABEL_2",
		72:  "MPLS_LABEL_3",
		73:  "MPLS_LABEL_4",
		74:  "MPLS_LABEL_5",
		75:  "MPLS_LABEL_6",
		76:  "MPLS_LABEL_7",
		77:  "MPLS_LABEL_8",
		78:  "MPLS_LABEL_9",
		79:  "MPLS_LABEL_10",
		80:  "IN_DST_MAC",
		81:  "OUT_SRC_MAC",
		82:  "IF_NAME",
		83:  "IF_DESC",
		84:  "SAMPLER_NAME",
		85:  "IN_ PERMANENT _BYTES",
		86:  "IN_ PERMANENT _PKTS",
		87:  "*Vendor Proprietary*",
		88:  "FRAGMENT_OFFSET",
		89:  "FORWARDING STATUS",
		90:  "MPLS PAL RD",
		91:  "MPLS PREFIX LEN",
		92:  "SRC TRAFFIC INDEX",
		93:  "DST TRAFFIC INDEX",
		94:  "APPLICATION DESCRIPTION",
		95:  "APPLICATION TAG",
		96:  "APPLICATION NAME",
		98:  "postipDiffServCodePoint",
		99:  "replication factor",
		100: "DEPRECATED",
		102: "layer2packetSectionOffset",
		103: "layer2packetSectionSize",
		104: "layer2packetSectionData",
		234: "ingressVRFID",
		235: "egressVRFID",
	}

	if typeId > 104 || typeId == 0 {
		return "Unassigned"
	} else {
		return nameList[typeId]
	}
}

func NFv9ScopeToString(scopeId uint16) string {
	nameList := map[uint16]string{
		1: "System",
		2: "Interface",
		3: "Line Card",
		4: "NetFlow Cache",
		5: "Template",
	}

	if scopeId >= 1 && scopeId <= 5 {
		return nameList[scopeId]
	} else {
		return "Unassigned"
	}
}

func (flowSet NFv9OptionsTemplateFlowSet) String(TypeToString func(uint16) string) string {
	str := fmt.Sprintf("       Id %v\n", flowSet.Id)
	str += fmt.Sprintf("       Length: %v\n", flowSet.Length)
	str += fmt.Sprintf("       Records (%v records):\n", len(flowSet.Records))

	for j, record := range flowSet.Records {
		str += fmt.Sprintf("       - Record %v:\n", j)
		str += fmt.Sprintf("            TemplateId: %v\n", record.TemplateId)
		str += fmt.Sprintf("            ScopeLength: %v\n", record.ScopeLength)
		str += fmt.Sprintf("            OptionLength: %v\n", record.OptionLength)
		str += fmt.Sprintf("            Scopes (%v):\n", len(record.Scopes))

		for k, field := range record.Scopes {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, NFv9ScopeToString(field.Type), field.Type, field.Length)
		}

		str += fmt.Sprintf("            Options (%v):\n", len(record.Options))

		for k, field := range record.Options {
			str += fmt.Sprintf("            - %v. %v (%v): %v\n", k, TypeToString(field.Type), field.Type, field.Length)
		}
	}

	return str
}

func (p NFv9Packet) String() string {
	str := "Flow Packet\n"
	str += "------------\n"
	str += fmt.Sprintf("  Version: %v\n", p.Version)
	str += fmt.Sprintf("  Count:  %v\n", p.Count)

	unixSeconds := time.Unix(int64(p.UnixSeconds), 0)
	str += fmt.Sprintf("  SystemUptime: %v\n", p.SystemUptime)
	str += fmt.Sprintf("  UnixSeconds: %v\n", unixSeconds.String())
	str += fmt.Sprintf("  SequenceNumber: %v\n", p.SequenceNumber)
	str += fmt.Sprintf("  SourceId: %v\n", p.SourceId)
	str += fmt.Sprintf("  FlowSets (%v):\n", len(p.FlowSets))

	for i, flowSet := range p.FlowSets {
		switch flowSet := flowSet.(type) {
		case TemplateFlowSet:
			str += fmt.Sprintf("    - TemplateFlowSet %v:\n", i)
			str += flowSet.String(NFv9TypeToString)
		case NFv9OptionsTemplateFlowSet:
			str += fmt.Sprintf("    - OptionsTemplateFlowSet %v:\n", i)
			str += flowSet.String(NFv9TypeToString)
		case DataFlowSet:
			str += fmt.Sprintf("    - DataFlowSet %v:\n", i)
			str += flowSet.String(NFv9TypeToString)
		case OptionsDataFlowSet:
			str += fmt.Sprintf("    - OptionsDataFlowSet %v:\n", i)
			str += flowSet.String(NFv9TypeToString, NFv9ScopeToString)
		default:
			str += fmt.Sprintf("    - (unknown type) %v: %v\n", i, flowSet)
		}
	}
	return str
}
