# GoFlow

This application is a NetFlow/IPFIX/sFlow collector in Go.

It gathers network information (IP, interfaces, routers) from different flow protocols,
serializes it in a protobuf format and sends the messages to Kafka using Sarama's library.

## Why

The diversity of devices and the amount of network samples at Cloudflare required its own pipeline.
We focused on building tools that could be easily monitored and maintained.
The main goal is to have full visibility of a network while allowing other teams to develop on it.

### Modularity

In order to enable load-balancing and optimizations, the GoFlow library has a `decoder` which converts
the payload of a flow packet into a Go structure.

The `producer` functions (one per protocol) then converts those structures into a protobuf (`pb/flow.pb`)
which contains the fields a network engineer is interested in.
The flow packets usually contains multiples samples
This acts as an abstraction of a sample.

The `transport` provides different way of processing the protobuf. Either sending it via Kafka or 
print it on the console.

Finally, `utils` provide functions that are directly used by the CLI utils.
GoFlow is a wrapper of all the functions and chains thems into producing bytes into Kafka.
There is also one CLI tool per protocol.

You can build your own collector using this base and replace parts:
* Use different transport (eg: RabbitMQ instead of Kafka)
* Convert to another format (eg: Cap'n Proto, Avro, instead of protobuf)
* Decode different samples (eg: not only IP networks, add MPLS)
* Different metrics system (eg: use [expvar](https://golang.org/pkg/expvar/) instead of Prometheus)

### Protocol difference

The sampling protocols can be very different:

**sFlow** is a stateless protocol which sends the full header of a packet with router information
(interfaces, destination AS) while **NetFlow/IPFIX** rely on templates that contain fields (eg: source IPv6).

The sampling rate in NetFlow/IPFIX is provided by **Option Data Sets**. This is why it can take a few minutes
for the packets to be decoded until all the templates are received (**Option Template** and **Data Template**).

Both of these protocols bundle multiple samples (**Data Set** in NetFlow/IPFIX and **Flow Sample** in sFlow)
in one packet.

The advantages of using an abstract network flow format, such as protobuf, is it enables summing over the
protocols (eg: per ASN or per port, rather than per (ASN, router) and (port, router)).

## Features

Collection:
* NetFlow v5
* IPFIX/NetFlow v9
  * Handles sampling rate provided by the Option Data Set
* sFlow v5: RAW, IPv4, IPv6, Ethernet samples, Gateway data, router data, switch data

Production:
* Convert to protobuf
* Sends to Kafka producer
* Prints to the console

Monitoring:
* Prometheus metrics
* Time to decode
* Samples rates
* Payload information
* NetFlow Templates

## Run

Download the latest release and just run the following command:

```
./goflow -h
```

Enable or disable a protocol using `-nf=false` or `-sflow=false`.
Define the port and addresses of the protocols using `-nf.addr`, `-nf.port` for NetFlow and `-sflow.addr`, `-slow.port` for sFlow.

Set the brokers or the Kafka brokers SRV record using: `-kafka.out.brokers 127.0.0.1:9092,[::1]:9092` or `-kafka.out.srv`.
Disable Kafka sending `-kafka=false`.
You can hash the protobuf by key when you send it to Kafka.

You can collect NetFlow/IPFIX, NetFlow v5 and sFlow using the same collector
or use the single-protocol collectors.

You can define the number of workers per protocol using `-workers` .

## Docker

We also provide a all-in-one Docker container. To run it in debug mode without sending into Kafka:

```
$ sudo docker run --net=host -ti cloudflare/goflow:latest -kafka=false
```

## Environment

To get an example of pipeline, check out [flow-pipeline](https://github.com/cloudflare/flow-pipeline)

### How is it used at Cloudflare

The samples flowing into Kafka are **processed** and special fields are inserted using other databases:
* User plan
* Country
* ASN and BGP information

The extended protobuf has the same base of the one in this repo. The **compatibility** with other software
is preserved when adding new fields (thus the fields will be lost if re-serialized).

Once the updated flows are back into Kafka, they are **consumed** by **database inserters** (Clickhouse, Amazon Redshift, Google BigTable...)
to allow for static analysis. Other teams access the network data just like any other log (SQL query).

### Output format

If you want to develop applications, build `pb/flow.proto` into the language you want:

Example in Go:
```
PROTOCPATH=$HOME/go/bin/ make proto
```

Example in Java:

```
export SRC_DIR="path/to/goflow-pb"
export DST_DIR="path/to/java/app/src/main/java"
protoc -I=$SRC_DIR --java_out=$DST_DIR $SRC_DIR/flow.proto
```

The fields are listed in the following table.

You can find information on how they are populated from the original source:
* For [sFlow](https://sflow.org/developers/specifications.php)
* For [NetFlow v5](https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html)
* For [NetFlow v9](https://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html)
* For [IPFIX](https://www.iana.org/assignments/ipfix/ipfix.xhtml)

| Field | Description | NetFlow v5 | sFlow | NetFlow v9 | IPFIX |
| - | - | - | - | - | - |
|Type|Type of flow message|NETFLOW_V5|SFLOW_5|NETFLOW_V9|IPFIX|
|TimeReceived|Timestamp of when the message was received|Included|Included|Included|Included|
|SequenceNum|Sequence number of the flow packet|Included|Included|Included|Included|
|SamplingRate|Sampling rate of the flow|Included|Included|Included|Included|
|FlowDirection|Direction of the flow| | |DIRECTION (61)|flowDirection (61)|
|SamplerAddress|Address of the device that generated the packet|IP source of packet|Agent IP|IP source of packet|IP source of packet|
|TimeFlowStart|Time the flow started|System uptime and first|=TimeReceived|System uptime and FIRST_SWITCHED (22)|flowStartXXX (150, 152, 154, 156)|
|TimeFlowEnd|Time the flow ended|System uptime and last|=TimeReceived|System uptime and LAST_SWITCHED (23)|flowEndXXX (151, 153, 155, 157)|
|Bytes|Number of bytes in flow|dOctets|Length of sample|IN_BYTES (1) OUT_BYTES (23)|octetDeltaCount (1) postOctetDeltaCount (23)|
|Packets|Number of packets in flow|dPkts|=1|IN_PKTS (2) OUT_PKTS (24)|packetDeltaCount (1) postPacketDeltaCount (24)|
|SrcAddr|Source address (IP)|srcaddr (IPv4 only)|Included|Included|IPV4_SRC_ADDR (8) IPV6_SRC_ADDR (27)|sourceIPv4Address/sourceIPv6Address (8/27)|
|DstAddr|Destination address (IP)|dstaddr (IPv4 only)|Included|Included|IPV4_DST_ADDR (12) IPV6_DST_ADDR (28)|destinationIPv4Address (12)destinationIPv6Address (28)|
|Etype|Ethernet type (0x86dd for IPv6...)|IPv4|Included|Included|Included|
|Proto|Protocol (UDP, TCP, ICMP...)|prot|Included|PROTOCOL (4)|protocolIdentifier (4)|
|SrcPort|Source port (when UDP/TCP/SCTP)|srcport|Included|L4_DST_PORT (11)|destinationTransportPort (11)|
|DstPort|Destination port (when UDP/TCP/SCTP)|dstport|Included|L4_SRC_PORT (7)|sourceTransportPort (7)|
|SrcIf|Source interface|input|Included|INPUT_SNMP (10)|ingressInterface (10)|
|DstIf|Destination interface|output|Included|OUTPUT_SNMP (14)|egressInterface (14)|
|SrcMac|Source mac address| |Included|IN_SRC_MAC (56)|sourceMacAddress (56)|
|DstMac|Destination mac address| |Included|OUT_DST_MAC (57)|postDestinationMacAddress (57)|
|SrcVlan|Source VLAN ID| |From ExtendedSwitch|SRC_VLAN (59)|vlanId (58)|
|DstVlan|Destination VLAN ID| |From ExtendedSwitch|DST_VLAN (59)|postVlanId (59)|
|VlanId|802.11q VLAN ID| |Included|SRC_VLAN (59)|postVlanId (59)|
|IngressVrfID|VRF ID| | | |ingressVRFID (234)| 
|EgressVrfID|VRF ID| | | |egressVRFID (235)|
|IPTos|IP Type of Service|tos|Included|SRC_TOS (5)|ipClassOfService (5)|
|ForwardingStatus|Forwarding status| | |FORWARDING_STATUS (89)|forwardingStatus (89)|
|IPTTL|IP Time to Live| |Included|IPTTL (52)|minimumTTL (52|
|TCPFlags|TCP flags|tcp_flags|Included|TCP_FLAGS (6)|tcpControlBits (6)|
|IcmpType|ICMP Type| |Included|ICMP_TYPE (32)|icmpTypeXXX (176, 178) icmpTypeCodeXXX (32, 139)|
|IcmpCode|ICMP Code| |Included|ICMP_TYPE (32)|icmpCodeXXX (177, 179) icmpTypeCodeXXX (32, 139)|
|IPv6FlowLabel|IPv6 Flow Label| |Included|IPV6_FLOW_LABEL (31)|flowLabelIPv6 (31)|
|FragmentId|IP Fragment ID| |Included|IPV4_IDENT (54)|fragmentIdentification (54)|
|FragmentOffset|IP Fragment Offset| |Included|FRAGMENT_OFFSET (88)|fragmentOffset (88)|
|BiFlowDirection|BiFlow Identification| | | |biflowDirection (239)|
|SrcAS|Source AS number|src_as|From ExtendedGateway|SRC_AS (16)|bgpSourceAsNumber (16)|
|DstAS|Destination AS number|dst_as|From ExtendedGateway|DST_AS (17)|bgpDestinationAsNumber (17)|
|NextHop|Nexthop address|nexthop|From ExtendedGateway|IPV4_NEXT_HOP (15) BGP_IPV4_NEXT_HOP (18) IPV6_NEXT_HOP (62) BGP_IPV6_NEXT_HOP (63)|ipNextHopIPv4Address (15) bgpNextHopIPv4Address (18) ipNextHopIPv6Address (62) bgpNextHopIPv6Address (63)|
|NextHopAS|Nexthop AS number| |From ExtendedGateway| | |
|SrcNet|Source address mask|src_mask|From ExtendedRouter|SRC_MASK (9) IPV6_SRC_MASK (29)|sourceIPv4PrefixLength (9) sourceIPv6PrefixLength (29)|
|DstNet|Destination address mask|dst_mask|From ExtendedRouter|DST_MASK (13) IPV6_DST_MASK (30)|destinationIPv4PrefixLength (13) destinationIPv6PrefixLength (30)|

If you are implementing flow processors to add more data to the protobuf,
we suggest you use field IDs ≥ 1000.

### Implementation notes

The pipeline at Cloudflare is connecting collectors with flow processors
that will add more information: with IP address, add country, ASN, etc.

For aggregation, we are using Materialized tables in Clickhouse.
Dictionaries help correlating flows with country and ASNs.
A few collectors can treat hundred of thousands of samples.

We also experimented successfully flow aggregation with Flink using a
[Keyed Session Window](https://ci.apache.org/projects/flink/flink-docs-release-1.4/dev/stream/operators/windows.html#session-windows):
this sums the `Bytes x SamplingRate` and `Packets x SamplingRate` received during a 5 minutes **window** while allowing 2 more minutes
in the case where some flows were delayed before closing the **session**.

The BGP information provided by routers can be unreliable (if the router does not have a BGP full-table or it is a static route).
You can use Maxmind [prefix to ASN](https://dev.maxmind.com/geoip/geoip2/geolite2/) in order to solve this issue.

## License

Licensed under the BSD 3 License.
