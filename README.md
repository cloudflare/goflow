# GoFlow

This application is a NetFlow/IPFIX/sFlow collector in Go.

It gather the network informations (IP, interfaces, routers) from the different flow protocols,
serialize it in a protobuf format and sends the message to Kafka using Sarama's library.

It can be configured to use multiple threads an do parallel processing of the incoming packets.
In production, it reached around 25000 messages per second for 20 workers, using approximately 2 CPU.

Some metrics are provided in the Prometheus format to monitor the samplers and the decoding speed.

## Command line

```
goflow
      -kafka=true
      -kafka.srv _logs-kafka._tcp.in.pdx.cfdata.org
      -kafka.topic netflows

      -netflow=true
      -fworkers 20
      -fport 2055

      -sflow=true
      -sworkers 3
      -sport 6343

      -metrics.addr :8080
      -uniquetemplates=false
      -sampling 16834
```