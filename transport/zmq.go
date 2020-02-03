package transport

/*
 * ZMQ Transport supporting JSON/Protbuf
 *
 * The zmq transport serializes the NetFlow/sFlow data as JSON objects or protobuf
 * and sends over [ZMQ](https://zeromq.org) and is intended to interop
 * with [ntopng](https://www.ntop.org/products/traffic-analysis/ntop/), filling
 * the same role a [nProbe](https://www.ntop.org/products/netflow/nprobe/) or your
 * own solution.
 */

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"github.com/cloudflare/goflow/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/cloudflare/goflow/utils"
	proto "github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
	"net"
	"strconv"
	"time"
)

var (
	ZmqListen    *string
	ZmqTopic     *string
	ZmqSourceId  *int
	ZmqSerialize *string
	ZmqCompress  *bool
)

type ZmqState struct {
	context   *zmq.Context
	publisher *zmq.Socket
	topic     *string
	log       *utils.Logger
	source_id *int
	serialize *string
	compress  *bool
}

/*
 * For more info on this you'll want to read:
 * ntop_typedefs.h, ntop_defines.h & CollectorInterface.cpp from
 * https://github.com/ntop/ntopng
 */
const ZMQ_MSG_VERSION = 2 // ntopng message version 2
var MessageId uint32 = 0  // Every ZMQ message we send should have a uniq ID

type ZmqHeader struct {
	url       [16]byte
	version   uint8
	source_id uint8
	length    uint16
	msg_id    uint32
}

// Serialize our ZmqHeader into a byte array
func (nh ZmqHeader) Bytes(topic string) *[]byte {
	var header []byte
	b1 := make([]byte, 1)
	b2 := make([]byte, 2)
	b4 := make([]byte, 4)

	// the url is really just the ZMQ topic
	url := make([]byte, len(nh.url))
	copy(url, []byte(topic))
	header = append(header[:], url[:]...)

	b1[0] = nh.version
	header = append(header[:], b1[:]...)

	// source_id in NetFlow is 32bit, but only 8bit here
	b1[0] = uint8(nh.source_id)
	header = append(header[:], b1[:]...)

	// length isn't actually used by the receiver, but we set it anyways
	binary.LittleEndian.PutUint16(b2, nh.length)
	header = append(header[:], b2[:]...)

	// only thing in network byte order for v2 header :-/
	MessageId++ // increment for each msg
	binary.BigEndian.PutUint32(b4, MessageId)
	header = append(header[:], b4[:]...)

	return &header
}

func RegisterZmqFlags() {
	ZmqListen = flag.String("zmq.listen", "tcp://*:5556", "IP/Port to listen for ZMQ connections")
	ZmqTopic = flag.String("zmq.topic", "flow", "ZMQ Topic to publish on")
	ZmqSourceId = flag.Int("zmq.source_id", 0x01, "NetFlow SourceId (0x01-0xff)")
	ZmqSerialize = flag.String("zmq.serialize", "json", "Serialize data as {json|pbuf}")
	ZmqCompress = flag.Bool("zmq.compress", false, "Compress json data")
}

func StartZmqProducer(listen string, topic string, log utils.Logger) (*ZmqState, error) {
	context, _ := zmq.NewContext()
	publisher, _ := context.NewSocket(zmq.PUB)
	publisher.Bind(listen)

	if *ZmqSerialize != "json" && *ZmqSerialize != "pbuf" {
		log.Fatalf("Invalid option: -zmq.serialize %s", *ZmqSerialize)
	}

	if *ZmqSourceId < 0 || *ZmqSourceId > 255 {
		log.Fatalf("Invalid option: -zmq.source_id %d", *ZmqSourceId)
	}

	//  Ensure subscriber connection has time to complete
	time.Sleep(time.Second)
	state := ZmqState{
		context:   context,
		publisher: publisher,
		topic:     &topic,
		log:       &log,
		source_id: ZmqSourceId,
		serialize: ZmqSerialize,
		compress:  ZmqCompress,
	}

	log.Infof("Started ZMQ listener on: %s", listen)
	return &state, nil
}

func StartZmqProducerFromArgs(log utils.Logger) (*ZmqState, error) {
	return StartZmqProducer(*ZmqListen, *ZmqTopic, log)
}

/*
 * Converts a FlowMessage to JSON for ntopng
 */
func (zs ZmqState) toJSON(flowMessage *flowmessage.FlowMessage) ([]byte, error) {
	ip6 := make(net.IP, net.IPv6len)
	ip4 := make(net.IP, net.IPv4len)
	hwaddr := make(net.HardwareAddr, 6)
	_hwaddr := make([]byte, binary.MaxVarintLen64)
	var icmp_type uint16
	retmap := make(map[string]interface{})

	// Stats + direction
	if flowMessage.FlowDirection == 0 {
		// ingress == 0
		retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 0
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_BYTES)] = flowMessage.Bytes
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_PKTS)] = flowMessage.Packets
	} else {
		// egress == 1
		retmap[strconv.Itoa(netflow.NFV9_FIELD_DIRECTION)] = 1
		retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_BYTES)] = flowMessage.Bytes
		retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_PKTS)] = flowMessage.Packets
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FIRST_SWITCHED)] = flowMessage.TimeFlowStart
	retmap[strconv.Itoa(netflow.NFV9_FIELD_LAST_SWITCHED)] = flowMessage.TimeFlowEnd

	// L4
	retmap[strconv.Itoa(netflow.NFV9_FIELD_PROTOCOL)] = flowMessage.Proto
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_SRC_PORT)] = flowMessage.SrcPort
	retmap[strconv.Itoa(netflow.NFV9_FIELD_L4_DST_PORT)] = flowMessage.DstPort

	// Network
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_AS)] = flowMessage.SrcAS
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_AS)] = flowMessage.DstAS

	// Interfaces
	retmap[strconv.Itoa(netflow.NFV9_FIELD_INPUT_SNMP)] = flowMessage.InIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUTPUT_SNMP)] = flowMessage.OutIf
	retmap[strconv.Itoa(netflow.NFV9_FIELD_FORWARDING_STATUS)] = flowMessage.ForwardingStatus
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_TOS)] = flowMessage.IPTos
	retmap[strconv.Itoa(netflow.NFV9_FIELD_TCP_FLAGS)] = flowMessage.TCPFlags
	retmap[strconv.Itoa(netflow.NFV9_FIELD_MIN_TTL)] = flowMessage.IPTTL

	// IP
	if flowMessage.Etype == 0x800 {
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 4
		// IPv4
		copy(ip4, flowMessage.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_ADDR)] = ip4.String()
		copy(ip4, flowMessage.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_ADDR)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_SRC_PREFIX)] = flowMessage.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_DST_PREFIX)] = flowMessage.DstNet
		copy(ip4, flowMessage.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_NEXT_HOP)] = ip4.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV4_IDENT)] = flowMessage.FragmentId
		retmap[strconv.Itoa(netflow.NFV9_FIELD_FRAGMENT_OFFSET)] = flowMessage.FragmentOffset
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = flowMessage.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = flowMessage.DstNet
	} else {
		// 0x86dd IPv6
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IP_PROTOCOL_VERSION)] = 6
		copy(ip6, flowMessage.SrcAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_ADDR)] = ip6.String()
		copy(ip6, flowMessage.DstAddr)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_ADDR)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_SRC_MASK)] = flowMessage.SrcNet
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_DST_MASK)] = flowMessage.DstNet
		copy(ip6, flowMessage.NextHop)
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_NEXT_HOP)] = ip6.String()
		retmap[strconv.Itoa(netflow.NFV9_FIELD_IPV6_FLOW_LABEL)] = flowMessage.IPv6FlowLabel
	}

	// ICMP
	icmp_type = uint16((uint16(flowMessage.IcmpType) << 8) + uint16(flowMessage.IcmpCode))
	retmap[strconv.Itoa(netflow.NFV9_FIELD_ICMP_TYPE)] = icmp_type

	// MAC
	binary.PutUvarint(_hwaddr, flowMessage.DstMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_IN_DST_MAC)] = hwaddr.String()
	binary.PutUvarint(_hwaddr, flowMessage.SrcMac)
	for i := 0; i < 6; i++ {
		hwaddr[i] = _hwaddr[i]
	}
	retmap[strconv.Itoa(netflow.NFV9_FIELD_OUT_SRC_MAC)] = hwaddr.String()

	// VLAN
	retmap[strconv.Itoa(netflow.NFV9_FIELD_SRC_VLAN)] = flowMessage.SrcVlan
	retmap[strconv.Itoa(netflow.NFV9_FIELD_DST_VLAN)] = flowMessage.DstVlan

	// convert to JSON
	jdata, err := json.Marshal(retmap)
	if err != nil {
		return jdata, err
	}

	if *zs.compress {
		var zbuf bytes.Buffer
		z := zlib.NewWriter(&zbuf)
		z.Write(jdata)
		z.Close()
		// must set jdata[0] = '\0' to indicate compressed data
		jdata = nil
		jdata = append(jdata, 0)
		jdata = append(jdata, zbuf.Bytes()...)
	}
	return jdata, nil
}

func (zs ZmqState) SendZmqMessage(flowMessage *flowmessage.FlowMessage) {
	log := *zs.log
	var msg []byte
	var err error

	if *zs.serialize == "pbuf" {
		msg, err = proto.Marshal(flowMessage)
	} else {
		msg, err = zs.toJSON(flowMessage)
	}

	if err != nil {
		log.Error(err)
		return
	}
	msg_len := uint16(len(msg))

	header := ZmqHeader{
		version:   ZMQ_MSG_VERSION,
		source_id: uint8(*zs.source_id),
		length:    msg_len,
	}

	// send our header with the topic first as a multi-part message
	hbytes := *header.Bytes(*zs.topic)
	bytes, err := zs.publisher.SendBytes(hbytes, zmq.SNDMORE)
	if err != nil {
		log.Error("Unable to send header: ", err)
		return
	}
	if bytes != len(hbytes) {
		log.Errorf("Wrote the wrong number of header bytes: %d", bytes)
		return
	}

	// now send the actual JSON payload
	bytes, err = zs.publisher.SendBytes(msg, 0)
	if err != nil {
		log.Error(err)
		return
	}
	if *zs.serialize == "json" {
		if *zs.compress {
			log.Debugf("sent %d bytes of zlib json:\n%s", msg_len, hex.Dump(msg))
		} else {
			log.Debugf("sent %d bytes of json: %s", msg_len, string(msg))
		}
	} else {
		log.Debugf("sent %d bytes of pbuf:\n%s", msg_len, hex.Dump(msg))
	}
}

func (zs ZmqState) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		zs.SendZmqMessage(msg)
	}
}
