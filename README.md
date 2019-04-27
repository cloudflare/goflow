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

You can collect NetFlow/IPFIX and sFlow using the same collector.

You can define the number of workers per protocol using `-fworkers` and `-sworkers`.

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

### Implementation notes

At Cloudflare, we used to aggregate flows in Flink using a
[Keyed Session Window](https://ci.apache.org/projects/flink/flink-docs-release-1.4/dev/stream/operators/windows.html#session-windows):
this sums the `Bytes x SamplingRate` and `Packets x SamplingRate` received during a 5 minutes **window** while allowing 2 more minutes
in the case where some flows were delayed before closing the **session**.

Currently, we are aggregating using Materialized tables in Clickhouse.
Dictionaries help correlating flows with country and ASNs.
A few collectors can treat hundred of thousands of samples.

The BGP information provided by routers can be unreliable (if the router does not have a BGP full-table or it is a static route).
You can use Maxmind [prefix to ASN](https://dev.maxmind.com/geoip/geoip2/geolite2/) in order to solve this issue.
We also gather the next-hops ASN using a custom BGP collector using [fgbgp library](https://github.com/cloudflare/fgbgp).

## License

Licensed under the BSD 3 License.
