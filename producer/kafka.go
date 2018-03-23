package producer

import (
	"errors"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	flowmessage "github.com/cloudflare/goflow/pb"
	proto "github.com/golang/protobuf/proto"
	sarama "gopkg.in/Shopify/sarama.v1"
	"net"
	"strconv"
	"strings"
)

var (
	KafkaTopic = flag.String("kafka.out.topic", "flow-messages", "Kafka topic to produce to")
	KafkaSrv   = flag.String("kafka.out.srv", "", "SRV record containing a list of Kafka brokers (or use kafka.out.brokers)")
	KafkaBrk   = flag.String("kafka.out.brokers", "127.0.0.1:9092,[::1]:9092", "Kafka brokers list separated by commas")
)

type KafkaState struct {
	producer sarama.AsyncProducer
}

func StartKafkaProducer() *KafkaState {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Producer.Return.Successes = false
	kafkaConfig.Producer.Return.Errors = false

	addrs := make([]string, 0)
	if *KafkaSrv != "" {
		addrs, _ = GetServiceAddresses(*KafkaSrv)
	} else {
		addrs = strings.Split(*KafkaBrk, ",")
	}

	kafkaProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	state := KafkaState{
		producer: kafkaProducer,
	}

	return &state
}

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

func (s KafkaState) SendKafkaFlowMessage(flowMessage flowmessage.FlowMessage) {
	b, _ := proto.Marshal(&flowMessage)
	s.producer.Input() <- &sarama.ProducerMessage{
		Topic: *KafkaTopic,
		Value: sarama.ByteEncoder(b),
	}
}
