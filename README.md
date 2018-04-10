# GoFlow

This application is a NetFlow/IPFIX/sFlow collector in Go.

It gather the network informations (IP, interfaces, routers) from the different flow protocols,
serialize it in a protobuf format and sends the message to Kafka using Sarama's library.

## Why

The diversity of devices and the amount of network samples at Cloudflare required its own pipeline.
We focused on building tools that could be easily monitored and maintainable.
The main goal is to have a full visibility of a network while allowing other teams to develop on it.

### Modularity

In order to enable load-balancing and optimizations, the GoFlow library has a `decoder` which converts
the payload of a flow packet into a Go structure.

The `producer` functions (one per protocol) then converts those structures into a protobuf (`pb/flow.pb`)
which contains the fields a network engineer is interested in.
The flow packets usually contains multiples samples
This acts as an abstraction of a sample.

GoFlow is a wrapper of all the functions and chains thems into producing bytes into Kafka.

You can build your own collector using this base and replace parts:
* Use different transport (eg: RabbitMQ instead of Kafka)
* Convert to another format (eg: Cap'n Proto, Avro, instead of protobuf)
* Decode different samples (eg: not only IP networks, add MPLS)
* Different metrics system (eg: use [expvar](https://golang.org/pkg/expvar/) instead of Prometheus)

Starting on v2.0.0: you have an increased flexibility and less inter-dependance in the code.

### Protocol difference

The sampling protocols can be very different:

**sFlow** is a stateless protocol which sends the full header of a packet with router information
(interfaces, destination AS) while **NetFlow/IPFIX** rely on templates that contains fields (eg: source IPv6)

The sampling rate in NetFlow/IPFIX is provided by **Option Data Sets**. This is why it can take a few minutes
for the packets to be decoded until all the templates are received (**Option Template** and **Data Template**).

Both of these protocols bundles multiples samples (**Data Set** in NetFlow/IPFIX and **Flow Sample** in sFlow)
in one packet

The advantages of using an abstract network flow format as protobuf enables summing over the protocols
(eg: per ASN or per port, rather than per (ASN, router) and (port, router)).

## Features

Collection:
* IPFIX/NetFlow v9
  * Handles sampling rate provided by the Option Data Set
* sFlow v5: RAW, IPv4, IPv6, Ethernet samples, Gateway data, router data, switch data

Production:
* Convert to protobuf
* Sends to Kafka producer

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

Enable or disable a protocol using `-netflow=false` or `-sflow=false`.
Define the port and addresses of the protocols using `-faddr`, `-fport` for NetFlow and `-saddr`, `-sport` for sFlow.

Set the `-loglevel` to `debug` mode to see what is received.

Set the brokers or the Kafka brokers SRV record using: `-kafka.out.brokers 127.0.0.1:9092,[::1]:9092` or `-kafka.out.srv`.
Disable Kafka sending `-kafka=false`.

You can collect NetFlow/IPFIX and sFlow using the same.

You can define the number of workers per protocol using `-fworkers` and `-sworkers`.

## Docker

We also provide a all-in-one Docker container. To run it in debug mode without sending into Kafka:

```
$ sudo docker run --net=host -ti cloudflare/goflow:latest -kafka=false -loglevel debug
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
They are also consumed by a Flink cluster in order to be **aggregated** and give live traffic information.

### Output format

If you want to develop applications, build `pb/flow.proto` into the language you want:

Example in Go:
```
export SRC_DIR="path/to/goflow-pb"
protoc --proto_path=$SRC_DIR --plugin=/path/to/bin/protoc-gen-go $SRC_DIR/flow.proto --go_out=$SRC_DIR

```

Example in Java:

```
export SRC_DIR="path/to/goflow-pb"
export DST_DIR="path/to/java/app/src/main/java"
protoc -I=$SRC_DIR --java_out=$DST_DIR $SRC_DIR/flow.proto

```

The format is the following:

| Field | Description |
| ----- | ----------- |
| FlowType | Indicates the protocol (IPFIX, NetFlow v9, sFlow v5) |
| TimeRecvd | Timestamp the packet was received by the collector |
| TimeFlow | Timestamp of the packet (same as TimeRecvd in sFlow, in NetFlow it's the uptime of the router minus LAST_SWITCHED field, in IPFIX it's flowEnd* field) |
| SamplingRate | Sampling rate of the flow, used to extrapolate the number of bytes and packets |
| SequenceNum | Sequence number of the packet |
| SrcIP | Source IP (sequence of bytes, can be IPv4 or IPv6) |
| DstIP | Destination IP (sequence of bytes, can be IPv4 or IPv6) |
| IPType | Indicates if IPv4 or IPv6), meant to be replaced by Etype |
| Bytes | Number of bytes in the sample |
| Packets | Number of packets in the sample |
| RouterAddr | Address of the router (UDP source in NetFlow/IPFIX, Agent IP in sFlow) |
| NextHop | Next-hop IP |
| NextHopAS | Next-hop ASN when the next-hop is a BGP neighbor (not all the flows) |
| SrcAS | Source ASN (provided by BGP) |
| DstAS | Destination ASN (provided by BGP) |
| SrcNet | Network mask of the source IP (provided by BGP) |
| DstNet | Network mask of the destination IP (provided by BGP) |
| SrcIf | Source interface ID (SNMP id) |
| DstIf | Destination interface ID (SNMP id) |
| Proto | Protocol code: TCP, UDP, etc. |
| SrcPort | Source port when proto is UDP/TCP |
| DstPort | Destination port when proto is UDP/TCP |
| IPTos | IPv4 type of service / Traffic class in IPv6 |
| ForwardingStatus | If the packet has been [dropped, consumed or forwarded](https://www.iana.org/assignments/ipfix/ipfix.xhtml#forwarding-status) |
| IPTTL | Time to Live of the IP packet |
| TCPFlags | Flags of the TCP Packet (SYN, ACK, etc.) |
| SrcMac | Source Mac Address |
| DstMac | Destination Mac Address |
| VlanId | Vlan when 802.1q |
| Etype | Ethernet type (IPv4, IPv6, ARP, etc.) |

### Implementation notes

At Cloudflare, we aggregate the flows in Flink using a 
[Keyed Session Windows](https://ci.apache.org/projects/flink/flink-docs-release-1.4/dev/stream/operators/windows.html#session-windows):
this sums the `Bytes x SamplingRate` and `Packets x SamplingRate` received during a 5 minutes **windows** while allowing 2 more minutes 
in the case where some flows were delayed before closing the **session**.

The BGP information provided by routers can be unreliable (if the router does not have a BGP full-table or it is a static route).
You can use Maxmind [prefix to ASN](https://dev.maxmind.com/geoip/geoip2/geolite2/) in order to solve this issue.
We also gather the next-hops ASN using a custom BGP collector using [fgbgp library](https://github.com/cloudflare/fgbgp).

## License

Licensed under the BSD 3 License.
