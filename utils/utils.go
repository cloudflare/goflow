package utils

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	decoder "github.com/cloudflare/goflow/v3/decoders"
	"github.com/cloudflare/goflow/v3/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
	reuseport "github.com/libp2p/go-reuseport"
	"github.com/prometheus/client_golang/prometheus"
)

const defaultFields = "Type,TimeReceived,SequenceNum,SamplingRate,SamplerAddress,TimeFlowStart,TimeFlowEnd,Bytes,Packets,SrcAddr,DstAddr,Etype,Proto,SrcPort,DstPort,InIf,OutIf,SrcMac,DstMac,SrcVlan,DstVlan,VlanId,IngressVrfID,EgressVrfID,IPTos,ForwardingStatus,IPTTL,TCPFlags,IcmpType,IcmpCode,IPv6FlowLabel,FragmentId,FragmentOffset,BiFlowDirection,SrcAS,DstAS,NextHop,NextHopAS,SrcNet,DstNet,HasEncap,SrcAddrEncap,DstAddrEncap,ProtoEncap,EtypeEncap,IPTosEncap,IPTTLEncap,IPv6FlowLabelEncap,FragmentIdEncap,FragmentOffsetEncap,HasMPLS,MPLSCount,MPLS1TTL,MPLS1Label,MPLS2TTL,MPLS2Label,MPLS3TTL,MPLS3Label,MPLSLastTTL,MPLSLastLabel,HasPPP,PPPAddressControl"

var (
	MessageFields = flag.String("message.fields", defaultFields, "The list of fields to include in flow messages")
)

func GetServiceAddresses(srv string) (addrs []string, err error) {
	_, srvs, err := net.LookupSRV("", "", srv)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Service discovery: %v\n", err))
	}
	for _, srv := range srvs {
		addrs = append(addrs, net.JoinHostPort(srv.Target, strconv.Itoa(int(srv.Port))))
	}
	return addrs, nil
}

type Logger interface {
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
	Warnf(string, ...interface{})
	Warn(...interface{})
	Error(...interface{})
	Debug(...interface{})
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Fatalf(string, ...interface{})
}

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte

	SetTime  bool
	RecvTime time.Time
}

type Transport interface {
	Publish([]*flowmessage.FlowMessage)
}

type DefaultLogTransport struct {
}

func (s *DefaultLogTransport) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		fmt.Printf("%v\n", FlowMessageToString(msg))
	}
}

type DefaultJSONTransport struct {
}

func (s *DefaultJSONTransport) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		fmt.Printf("%v\n", FlowMessageToJSON(msg))
	}
}

type DefaultErrorCallback struct {
	Logger Logger
}

func (cb *DefaultErrorCallback) Callback(name string, id int, start, end time.Time, err error) {
	if _, ok := err.(*netflow.ErrorTemplateNotFound); ok {
		return
	}
	if cb.Logger != nil {
		cb.Logger.Errorf("Error from: %v (%v) duration: %v. %v", name, id, end.Sub(start), err)
	}
}

type flowMessageItem struct {
	Name, Value string
}

func flowMessageFiltered(fmsg *flowmessage.FlowMessage) []flowMessageItem {
	srcmac := make([]byte, 8)
	dstmac := make([]byte, 8)
	binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
	binary.BigEndian.PutUint64(dstmac, fmsg.DstMac)
	srcmac = srcmac[2:8]
	dstmac = dstmac[2:8]
	var message []flowMessageItem

	for _, field := range strings.Split(*MessageFields, ",") {
		switch field {
		case "Type":
			message = append(message, flowMessageItem{"Type", fmsg.Type.String()})
		case "TimeReceived":
			message = append(message, flowMessageItem{"TimeReceived", fmt.Sprintf("%v", fmsg.TimeReceived)})
		case "SequenceNum":
			message = append(message, flowMessageItem{"SequenceNum", fmt.Sprintf("%v", fmsg.SequenceNum)})
		case "SamplingRate":
			message = append(message, flowMessageItem{"SamplingRate", fmt.Sprintf("%v", fmsg.SamplingRate)})
		case "SamplerAddress":
			message = append(message, flowMessageItem{"SamplerAddress", net.IP(fmsg.SamplerAddress).String()})
		case "TimeFlowStart":
			message = append(message, flowMessageItem{"TimeFlowStart", fmt.Sprintf("%v", fmsg.TimeFlowStart)})
		case "TimeFlowEnd":
			message = append(message, flowMessageItem{"TimeFlowEnd", fmt.Sprintf("%v", fmsg.TimeFlowEnd)})
		case "Bytes":
			message = append(message, flowMessageItem{"Bytes", fmt.Sprintf("%v", fmsg.Bytes)})
		case "Packets":
			message = append(message, flowMessageItem{"Packets", fmt.Sprintf("%v", fmsg.Packets)})
		case "SrcAddr":
			message = append(message, flowMessageItem{"SrcAddr", net.IP(fmsg.SrcAddr).String()})
		case "DstAddr":
			message = append(message, flowMessageItem{"DstAddr", net.IP(fmsg.DstAddr).String()})
		case "Etype":
			message = append(message, flowMessageItem{"Etype", fmt.Sprintf("%v", fmsg.Etype)})
		case "Proto":
			message = append(message, flowMessageItem{"Proto", fmt.Sprintf("%v", fmsg.Proto)})
		case "SrcPort":
			message = append(message, flowMessageItem{"SrcPort", fmt.Sprintf("%v", fmsg.SrcPort)})
		case "DstPort":
			message = append(message, flowMessageItem{"DstPort", fmt.Sprintf("%v", fmsg.DstPort)})
		case "InIf":
			message = append(message, flowMessageItem{"InIf", fmt.Sprintf("%v", fmsg.InIf)})
		case "OutIf":
			message = append(message, flowMessageItem{"OutIf", fmt.Sprintf("%v", fmsg.OutIf)})
		case "SrcMac":
			message = append(message, flowMessageItem{"SrcMac", net.HardwareAddr(srcmac).String()})
		case "DstMac":
			message = append(message, flowMessageItem{"DstMac", net.HardwareAddr(dstmac).String()})
		case "SrcVlan":
			message = append(message, flowMessageItem{"SrcVlan", fmt.Sprintf("%v", fmsg.SrcVlan)})
		case "DstVlan":
			message = append(message, flowMessageItem{"DstVlan", fmt.Sprintf("%v", fmsg.DstVlan)})
		case "VlanId":
			message = append(message, flowMessageItem{"VlanId", fmt.Sprintf("%v", fmsg.VlanId)})
		case "IngressVrfID":
			message = append(message, flowMessageItem{"IngressVrfID", fmt.Sprintf("%v", fmsg.IngressVrfID)})
		case "EgressVrfID":
			message = append(message, flowMessageItem{"EgressVrfID", fmt.Sprintf("%v", fmsg.EgressVrfID)})
		case "IPTos":
			message = append(message, flowMessageItem{"IPTos", fmt.Sprintf("%v", fmsg.IPTos)})
		case "ForwardingStatus":
			message = append(message, flowMessageItem{"ForwardingStatus", fmt.Sprintf("%v", fmsg.ForwardingStatus)})
		case "IPTTL":
			message = append(message, flowMessageItem{"IPTTL", fmt.Sprintf("%v", fmsg.IPTTL)})
		case "TCPFlags":
			message = append(message, flowMessageItem{"TCPFlags", fmt.Sprintf("%v", fmsg.TCPFlags)})
		case "IcmpType":
			message = append(message, flowMessageItem{"IcmpType", fmt.Sprintf("%v", fmsg.IcmpType)})
		case "IcmpCode":
			message = append(message, flowMessageItem{"IcmpCode", fmt.Sprintf("%v", fmsg.IcmpCode)})
		case "IPv6FlowLabel":
			message = append(message, flowMessageItem{"IPv6FlowLabel", fmt.Sprintf("%v", fmsg.IPv6FlowLabel)})
		case "FragmentId":
			message = append(message, flowMessageItem{"FragmentId", fmt.Sprintf("%v", fmsg.FragmentId)})
		case "FragmentOffset":
			message = append(message, flowMessageItem{"FragmentOffset", fmt.Sprintf("%v", fmsg.FragmentOffset)})
		case "BiFlowDirection":
			message = append(message, flowMessageItem{"BiFlowDirection", fmt.Sprintf("%v", fmsg.BiFlowDirection)})
		case "SrcAS":
			message = append(message, flowMessageItem{"SrcAS", fmt.Sprintf("%v", fmsg.SrcAS)})
		case "DstAS":
			message = append(message, flowMessageItem{"DstAS", fmt.Sprintf("%v", fmsg.DstAS)})
		case "NextHop":
			message = append(message, flowMessageItem{"NextHop", net.IP(fmsg.NextHop).String()})
		case "NextHopAS":
			message = append(message, flowMessageItem{"NextHopAS", fmt.Sprintf("%v", fmsg.NextHopAS)})
		case "SrcNet":
			message = append(message, flowMessageItem{"SrcNet", fmt.Sprintf("%v", fmsg.SrcNet)})
		case "DstNet":
			message = append(message, flowMessageItem{"DstNet", fmt.Sprintf("%v", fmsg.DstNet)})
		case "HasEncap":
			message = append(message, flowMessageItem{"HasEncap", fmt.Sprintf("%v", fmsg.HasEncap)})
		case "SrcAddrEncap":
			message = append(message, flowMessageItem{"SrcAddrEncap", net.IP(fmsg.SrcAddrEncap).String()})
		case "DstAddrEncap":
			message = append(message, flowMessageItem{"DstAddrEncap", net.IP(fmsg.DstAddrEncap).String()})
		case "ProtoEncap":
			message = append(message, flowMessageItem{"ProtoEncap", fmt.Sprintf("%v", fmsg.ProtoEncap)})
		case "EtypeEncap":
			message = append(message, flowMessageItem{"EtypeEncap", fmt.Sprintf("%v", fmsg.EtypeEncap)})
		case "IPTosEncap":
			message = append(message, flowMessageItem{"IPTosEncap", fmt.Sprintf("%v", fmsg.IPTosEncap)})
		case "IPTTLEncap":
			message = append(message, flowMessageItem{"IPTTLEncap", fmt.Sprintf("%v", fmsg.IPTTLEncap)})
		case "IPv6FlowLabelEncap":
			message = append(message, flowMessageItem{"IPv6FlowLabelEncap", fmt.Sprintf("%v", fmsg.IPv6FlowLabelEncap)})
		case "FragmentIdEncap":
			message = append(message, flowMessageItem{"FragmentIdEncap", fmt.Sprintf("%v", fmsg.FragmentIdEncap)})
		case "FragmentOffsetEncap":
			message = append(message, flowMessageItem{"FragmentOffsetEncap", fmt.Sprintf("%v", fmsg.FragmentOffsetEncap)})
		case "HasMPLS":
			message = append(message, flowMessageItem{"HasMPLS", fmt.Sprintf("%v", fmsg.HasMPLS)})
		case "MPLSCount":
			message = append(message, flowMessageItem{"MPLSCount", fmt.Sprintf("%v", fmsg.MPLSCount)})
		case "MPLS1TTL":
			message = append(message, flowMessageItem{"MPLS1TTL", fmt.Sprintf("%v", fmsg.MPLS1TTL)})
		case "MPLS1Label":
			message = append(message, flowMessageItem{"MPLS1Label", fmt.Sprintf("%v", fmsg.MPLS1Label)})
		case "MPLS2TTL":
			message = append(message, flowMessageItem{"MPLS2TTL", fmt.Sprintf("%v", fmsg.MPLS2TTL)})
		case "MPLS2Label":
			message = append(message, flowMessageItem{"MPLS2Label", fmt.Sprintf("%v", fmsg.MPLS2Label)})
		case "MPLS3TTL":
			message = append(message, flowMessageItem{"MPLS3TTL", fmt.Sprintf("%v", fmsg.MPLS3TTL)})
		case "MPLS3Label":
			message = append(message, flowMessageItem{"MPLS3Label", fmt.Sprintf("%v", fmsg.MPLS3Label)})
		case "MPLSLastTTL":
			message = append(message, flowMessageItem{"MPLSLastTTL", fmt.Sprintf("%v", fmsg.MPLSLastTTL)})
		case "MPLSLastLabel":
			message = append(message, flowMessageItem{"MPLSLastLabel", fmt.Sprintf("%v", fmsg.MPLSLastLabel)})
		case "HasPPP":
			message = append(message, flowMessageItem{"HasPPP", fmt.Sprintf("%v", fmsg.HasPPP)})
		case "PPPAddressControl":
			message = append(message, flowMessageItem{"PPPAddressControl", fmt.Sprintf("%v", fmsg.PPPAddressControl)})
		}
	}

	return message
}

func FlowMessageToString(fmsg *flowmessage.FlowMessage) string {
	filteredMessage := flowMessageFiltered(fmsg)
	message := make([]string, len(filteredMessage))
	for i, m := range filteredMessage {
		message[i] = m.Name + ":" + m.Value
	}
	return strings.Join(message, " ")
}

func FlowMessageToJSON(fmsg *flowmessage.FlowMessage) string {
	filteredMessage := flowMessageFiltered(fmsg)
	message := make([]string, len(filteredMessage))
	for i, m := range filteredMessage {
		message[i] = fmt.Sprintf("\"%s\":\"%s\"", m.Name, m.Value)
	}
	return "{" + strings.Join(message, ",") + "}"
}

func UDPRoutine(name string, decodeFunc decoder.DecoderFunc, workers int, addr string, port int, sockReuse bool, logger Logger) error {
	ecb := DefaultErrorCallback{
		Logger: logger,
	}

	decoderParams := decoder.DecoderParams{
		DecoderFunc:   decodeFunc,
		DoneCallback:  DefaultAccountCallback,
		ErrorCallback: ecb.Callback,
	}

	processor := decoder.CreateProcessor(workers, decoderParams, name)
	processor.Start()

	addrUDP := net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	}

	var udpconn *net.UDPConn
	var err error

	if sockReuse {
		pconn, err := reuseport.ListenPacket("udp", addrUDP.String())
		defer pconn.Close()
		if err != nil {
			return err
		}
		var ok bool
		udpconn, ok = pconn.(*net.UDPConn)
		if !ok {
			return err
		}
	} else {
		udpconn, err = net.ListenUDP("udp", &addrUDP)
		defer udpconn.Close()
		if err != nil {
			return err
		}
	}

	payload := make([]byte, 9000)

	localIP := addrUDP.IP.String()
	if addrUDP.IP == nil {
		localIP = ""
	}

	for {
		size, pktAddr, _ := udpconn.ReadFromUDP(payload)
		payloadCut := make([]byte, size)
		copy(payloadCut, payload[0:size])

		baseMessage := BaseMessage{
			Src:     pktAddr.IP,
			Port:    pktAddr.Port,
			Payload: payloadCut,
		}
		processor.ProcessMessage(baseMessage)

		MetricTrafficBytes.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Add(float64(size))
		MetricTrafficPackets.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Inc()
		MetricPacketSizeSum.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Observe(float64(size))
	}
}
