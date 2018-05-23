package transport

import (
	log "github.com/Sirupsen/logrus"
	flowmessage "github.com/cloudflare/goflow/pb"
	proto "github.com/golang/protobuf/proto"
	sarama "gopkg.in/Shopify/sarama.v1"
)

type KafkaState struct {
	producer sarama.AsyncProducer
	topic    string
}

func StartKafkaProducer(addrs []string, topic string) *KafkaState {
	kafkaConfig := sarama.NewConfig()
	kafkaConfig.Producer.Return.Successes = false
	kafkaConfig.Producer.Return.Errors = false

	kafkaProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}
	state := KafkaState{
		producer: kafkaProducer,
		topic: topic,
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
