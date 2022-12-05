module github.com/kbatyr/goflow/v3

go 1.12

require (
	github.com/Shopify/sarama v1.27.0
	github.com/cloudflare/goflow/v3 v3.0.0-00010101000000-000000000000
	github.com/golang/protobuf v1.3.1
	github.com/google/gopacket v1.1.18
	github.com/libp2p/go-reuseport v0.0.1
	github.com/prometheus/client_golang v0.9.2
	github.com/sirupsen/logrus v1.4.1
	github.com/stretchr/testify v1.8.0
)

replace github.com/cloudflare/goflow/v3 => github.com/kbatyr/goflow/v3 v3.5.0
