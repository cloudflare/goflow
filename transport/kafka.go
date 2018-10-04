package transport

import (
	"crypto/tls"
	"crypto/x509"
	log "github.com/Sirupsen/logrus"
	flowmessage "github.com/cloudflare/goflow/pb"
	proto "github.com/golang/protobuf/proto"
	sarama "gopkg.in/Shopify/sarama.v1"
)

type KafkaState struct {
	producer sarama.AsyncProducer
	topic    string
}

func StartKafkaProducer(addrs []string, topic string, use_tls bool) *KafkaState {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Producer.Return.Successes = false
	kafkaConfig.Producer.Return.Errors = false
	if use_tls {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			log.Fatalf("Error initializing TLS: %v", err)
		}
		kafkaConfig.Net.TLS.Enable = true
		kafkaConfig.Net.TLS.Config = &tls.Config{RootCAs: rootCAs}
	}

	kafkaProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	state := KafkaState{
		producer: kafkaProducer,
		topic:    topic,
	}

	return &state
}

func (s KafkaState) SendKafkaFlowMessage(flowMessage *flowmessage.FlowMessage) {
	b, _ := proto.Marshal(flowMessage)
	s.producer.Input() <- &sarama.ProducerMessage{
		Topic: s.topic,
		Value: sarama.ByteEncoder(b),
	}
}
