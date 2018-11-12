package transport

import (
	"crypto/tls"
	"crypto/x509"
	log "github.com/Sirupsen/logrus"
	flowmessage "github.com/cloudflare/goflow/pb"
	proto "github.com/golang/protobuf/proto"
	sarama "gopkg.in/Shopify/sarama.v1"
	"os"
)

type KafkaState struct {
	producer sarama.AsyncProducer
	topic    string
	key      sarama.Encoder
}

func StartKafkaProducer(addrs []string, topic string, key string, use_tls bool, use_sasl bool) *KafkaState {
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
	if use_sasl {
		if !use_tls {
			log.Warnln("Using SASL without TLS will transmit the authentication in plaintext!")
		}
		kafkaConfig.Net.SASL.Enable = true
		kafkaConfig.Net.SASL.User = os.Getenv("KAFKA_SASL_USER")
		kafkaConfig.Net.SASL.Password = os.Getenv("KAFKA_SASL_PASS")
		if kafkaConfig.Net.SASL.User == "" && kafkaConfig.Net.SASL.Password == "" {
			log.Fatalf("Kafka SASL config from environment was unsuccessful. KAFKA_SASL_USER and KAFKA_SASL_PASS need to be set.")
		} else {
			log.Infof("Authenticating as user '%s'...", kafkaConfig.Net.SASL.User)
		}
	}

	kafkaProducer, err := sarama.NewAsyncProducer(addrs, kafkaConfig)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var keyEncoder sarama.Encoder
	if key != "" {
		keyEncoder = sarama.StringEncoder(key)
	}

	state := KafkaState{
		producer: kafkaProducer,
		topic:    topic,
		key:      keyEncoder,
	}

	return &state
}

func (s KafkaState) SendKafkaFlowMessage(flowMessage *flowmessage.FlowMessage) {
	b, _ := proto.Marshal(flowMessage)
	s.producer.Input() <- &sarama.ProducerMessage{
		Topic: s.topic,
		Key:   s.key,
		Value: sarama.ByteEncoder(b),
	}
}
