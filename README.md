# GoFlow ClickHouse

This is a fork of cloudflare's GoFlow, is a NetFlow/IPFIX/sFlow collector in Go.

It gathers network information (IP, interfaces, routers) from different flow protocols,
serializes it in a protobuf format and ~~sends the messages to Kafka using Sarama's library~~ stores the indexed data into [ClickHouse](https://clickhouse.tech/),
a FOSS, blazing-fast column based DB great for persistent storage of repetitive data.

Just to put Java out of the loop :)

If ClickHouse runs out RAM during search at any point, simply put `<max_server_memory_usage_to_ram_ratio>2</max_server_memory_usage_to_ram_ratio>` in it's config file.

(You will need to setup ClickHouse separately)

## TLDR; / quick start

To quickly get started, simply run `make build-goflow` and get the binary in `dist/` folder. 

## Limitations of the ClickHouse fork

MPLS data is also not recorded. However, it'd be very easy to change the code to fit those changes, simply modify the schema and the publish functions.

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

The `transport` provides clickhouse storage.

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
```
./goflow -ch.database="homestat" -ch.table="nflowVPN" -ch.addr="127.0.0.1" -ch.username="default" -ch.password="" -loglevel="debug" -sflow="false" -nfl="false" -metrics.addr="0.0.0.0:8057" -nf.port="2057" -nf.addr="xxx.xxx.xxx.xxx"
```


## License

Licensed under the BSD 3 License.
