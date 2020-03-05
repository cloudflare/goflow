package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	decoder "github.com/cloudflare/goflow/v3/decoders"
	"github.com/cloudflare/goflow/v3/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
	reuseport "github.com/libp2p/go-reuseport"
	"github.com/prometheus/client_golang/prometheus"
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

func FlowMessageToString(fmsg *flowmessage.FlowMessage) string {
	srcmac := make([]byte, 8)
	dstmac := make([]byte, 8)
	binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
	binary.BigEndian.PutUint64(dstmac, fmsg.DstMac)
	srcmac = srcmac[2:8]
	dstmac = dstmac[2:8]

	s := fmt.Sprintf("Type:%v TimeReceived:%v SequenceNum:%v SamplingRate:%v "+
		"SamplerAddress:%v TimeFlowStart:%v TimeFlowEnd:%v Bytes:%v Packets:%v SrcAddr:%v "+
		"DstAddr:%v Etype:%v Proto:%v SrcPort:%v DstPort:%v InIf:%v OutIf:%v SrcMac:%v "+
		"DstMac:%v SrcVlan:%v DstVlan:%v VlanId:%v IngressVrfID:%v EgressVrfID:%v IPTos:%v "+
		"ForwardingStatus:%v IPTTL:%v TCPFlags:%v IcmpType:%v IcmpCode:%v IPv6FlowLabel:%v "+
		"FragmentId:%v FragmentOffset:%v BiFlowDirection:%v SrcAS:%v DstAS:%v NextHop:%v NextHopAS:%v SrcNet:%v DstNet:%v "+
		"HasEncap:%v SrcAddrEncap:%v DstAddrEncap:%v ProtoEncap:%v EtypeEncap:%v "+
		"IPTosEncap:%v IPTTLEncap:%v IPv6FlowLabelEncap:%v FragmentIdEncap:%v FragmentOffsetEncap:%v "+
		"HasMPLS:%v MPLSCount:%v MPLS1TTL:%v MPLS1Label:%v MPLS2TTL:%v, MPLS2Label: %v, MPLS3TTL:%v MPLS3Label:%v MPLSLastTTL:%v MPLSLastLabel:%v "+
		"HasPPP:%v PPPAddressControl:%v",
		fmsg.Type, fmsg.TimeReceived, fmsg.SequenceNum, fmsg.SamplingRate, net.IP(fmsg.SamplerAddress),
		fmsg.TimeFlowStart, fmsg.TimeFlowEnd, fmsg.Bytes, fmsg.Packets, net.IP(fmsg.SrcAddr), net.IP(fmsg.DstAddr),
		fmsg.Etype, fmsg.Proto, fmsg.SrcPort, fmsg.DstPort, fmsg.InIf, fmsg.OutIf, net.HardwareAddr(srcmac),
		net.HardwareAddr(dstmac), fmsg.SrcVlan, fmsg.DstVlan, fmsg.VlanId, fmsg.IngressVrfID,
		fmsg.EgressVrfID, fmsg.IPTos, fmsg.ForwardingStatus, fmsg.IPTTL, fmsg.TCPFlags, fmsg.IcmpType,
		fmsg.IcmpCode, fmsg.IPv6FlowLabel, fmsg.FragmentId, fmsg.FragmentOffset, fmsg.BiFlowDirection, fmsg.SrcAS, fmsg.DstAS,
		net.IP(fmsg.NextHop), fmsg.NextHopAS, fmsg.SrcNet, fmsg.DstNet,
		fmsg.HasEncap, net.IP(fmsg.SrcAddrEncap), net.IP(fmsg.DstAddrEncap), fmsg.ProtoEncap, fmsg.EtypeEncap,
		fmsg.IPTosEncap, fmsg.IPTTLEncap, fmsg.IPv6FlowLabelEncap, fmsg.FragmentIdEncap, fmsg.FragmentOffsetEncap,
		fmsg.HasMPLS, fmsg.MPLSCount, fmsg.MPLS1TTL, fmsg.MPLS1Label, fmsg.MPLS2TTL, fmsg.MPLS2Label, fmsg.MPLS3TTL, fmsg.MPLS3Label, fmsg.MPLSLastTTL, fmsg.MPLSLastLabel,
		fmsg.HasPPP, fmsg.PPPAddressControl)
	return s
}

func FlowMessageToJSON(fmsg *flowmessage.FlowMessage) string {
	srcmac := make([]byte, 8)
	dstmac := make([]byte, 8)
	binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
	binary.BigEndian.PutUint64(dstmac, fmsg.DstMac)
	srcmac = srcmac[2:8]
	dstmac = dstmac[2:8]

	s := fmt.Sprintf("{\"Type\":\"%v\",\"TimeReceived\":%v,\"SequenceNum\":%v,\"SamplingRate\":%v,"+
		"\"SamplerAddress\":\"%v\",\"TimeFlowStart\":%v,\"TimeFlowEnd\":%v,\"Bytes\":%v,\"Packets\":%v,\"SrcAddr\":\"%v\","+
		"\"DstAddr\":\"%v\",\"Etype\":%v,\"Proto\":%v,\"SrcPort\":%v,\"DstPort\":%v,\"InIf\":%v,\"OutIf\":%v,\"SrcMac\":\"%v\","+
		"\"DstMac\":\"%v\",\"SrcVlan\":%v,\"DstVlan\":%v,\"VlanId\":%v,\"IngressVrfID\":%v,\"EgressVrfID\":%v,\"IPTos\":%v,"+
		"\"ForwardingStatus\":%v,\"IPTTL\":%v,\"TCPFlags\":%v,\"IcmpType\":%v,\"IcmpCode\":%v,\"IPv6FlowLabel\":%v,"+
		"\"FragmentId\":%v,\"FragmentOffset\":%v,\"BiFlowDirection\":%v,\"SrcAS\":%v,\"DstAS\":%v,\"NextHop\":\"%v\",\"NextHopAS\":%v,\"SrcNet\":%v,\"DstNet\":%v,"+
		"\"HasEncap\":%v,\"SrcAddrEncap\":\"%v\",\"DstAddrEncap\":\"%v\",\"ProtoEncap\":%v,\"EtypeEncap\":%v,"+
		"\"IPTosEncap\":%v,\"IPTTLEncap\":%v,\"IPv6FlowLabelEncap\":%v,\"FragmentIdEncap\":%v,\"FragmentOffsetEncap\":%v,"+
		"\"HasMPLS\":%v,\"MPLSCount\":%v,\"MPLS1TTL\":%v,\"MPLS1Label\":%v,\"MPLS2TTL\":%v,\"MPLS2Label\":%v,\"MPLS3TTL\":%v,\"MPLS3Label\":%v,\"MPLSLastTTL\":%v,\"MPLSLastLabel\":%v,"+
		"\"HasPPP\":%v,\"PPPAddressControl\":%v}",
		fmsg.Type, fmsg.TimeReceived, fmsg.SequenceNum, fmsg.SamplingRate, net.IP(fmsg.SamplerAddress),
		fmsg.TimeFlowStart, fmsg.TimeFlowEnd, fmsg.Bytes, fmsg.Packets, net.IP(fmsg.SrcAddr), net.IP(fmsg.DstAddr),
		fmsg.Etype, fmsg.Proto, fmsg.SrcPort, fmsg.DstPort, fmsg.InIf, fmsg.OutIf, net.HardwareAddr(srcmac),
		net.HardwareAddr(dstmac), fmsg.SrcVlan, fmsg.DstVlan, fmsg.VlanId, fmsg.IngressVrfID,
		fmsg.EgressVrfID, fmsg.IPTos, fmsg.ForwardingStatus, fmsg.IPTTL, fmsg.TCPFlags, fmsg.IcmpType,
		fmsg.IcmpCode, fmsg.IPv6FlowLabel, fmsg.FragmentId, fmsg.FragmentOffset, fmsg.BiFlowDirection, fmsg.SrcAS, fmsg.DstAS,
		net.IP(fmsg.NextHop), fmsg.NextHopAS, fmsg.SrcNet, fmsg.DstNet,
		fmsg.HasEncap, net.IP(fmsg.SrcAddrEncap), net.IP(fmsg.DstAddrEncap), fmsg.ProtoEncap, fmsg.EtypeEncap,
		fmsg.IPTosEncap, fmsg.IPTTLEncap, fmsg.IPv6FlowLabelEncap, fmsg.FragmentIdEncap, fmsg.FragmentOffsetEncap,
		fmsg.HasMPLS, fmsg.MPLSCount, fmsg.MPLS1TTL, fmsg.MPLS1Label, fmsg.MPLS2TTL, fmsg.MPLS2Label, fmsg.MPLS3TTL, fmsg.MPLS3Label, fmsg.MPLSLastTTL, fmsg.MPLSLastLabel,
		fmsg.HasPPP, fmsg.PPPAddressControl)
	return s
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
