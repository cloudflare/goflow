package transport

import (
	"flag"

	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/cloudflare/goflow/v3/utils"
	"github.com/golang/protobuf/proto"
	"github.com/nats-io/nats.go"
	"time"
)

var (
	natsSubject        string
	natsURL            string
	natsCAPath         []string
	natsUser           string
	natsPass           string
	natsClientCertFile string
	natsClientKeyFile  string
	natsDialTimeout    time.Duration
	natsPingInterval   time.Duration
	natsMaxReconnect   int
	natsReconnectWait  time.Duration
)

func registerNatsFlags() {
	flag.StringVar(&natsSubject, "nats.subject", "flow-messages", "Nats subject to publish on")
	flag.StringVar(&natsURL, "nats.url", nats.DefaultURL, "Nats URL to connect")
	flag.Var((*stringSliceFlag)(&natsCAPath), "nats.root-ca-path", "Root ca paths.  can be specified multiple times for multiple CA paths or separated by comma")
	flag.StringVar(&natsClientCertFile, "nats.client-cert", "", "Path to the nats client certificate if client auth is to be used.")
	flag.StringVar(&natsClientKeyFile, "nats.client-key", "", "Path to the nats client private key if client auth is to be used.")
	flag.StringVar(&natsUser, "nats.user", "", "Nats username")
	flag.StringVar(&natsPass, "nats.password", "", "Nats password")
	flag.DurationVar(&natsDialTimeout, "nats.dialtimeout", nats.GetDefaultOptions().Timeout, "Nats dial timeout for connecting to server(s).")
	flag.DurationVar(&natsPingInterval, "nats.ping_interval", nats.GetDefaultOptions().PingInterval, "Nats ping interval")
	flag.IntVar(&natsMaxReconnect, "nats.max_reconnect", nats.GetDefaultOptions().MaxReconnect, "Nats max reconnects before giving up")
	flag.DurationVar(&natsReconnectWait, "nats.reconnect_wait", nats.GetDefaultOptions().ReconnectWait, "Nats reconnect wait between attempts")
}

type natsState struct {
	FixedLengthProto bool
	conn             *nats.Conn
	subject          string
	l                utils.Logger
}

func (n natsState) publishMessage(flowMessage *flowmessage.FlowMessage) error {
	var b []byte
	if !n.FixedLengthProto {
		b, _ = proto.Marshal(flowMessage)
	} else {
		buf := proto.NewBuffer([]byte{})
		buf.EncodeMessage(flowMessage)
		b = buf.Bytes()
	}
	return n.conn.Publish(n.subject, b)
}

func (n natsState) Publish(messages []*flowmessage.FlowMessage) {
	for _, m := range messages {
		err := n.publishMessage(m)
		if err != nil {
			n.l.Errorf("error on publish: %s", err)
		}
	}
}

func StartNatsTransportFromArgs(logger utils.Logger) (*natsState, error) {
	var options = []nats.Option{
		nats.Timeout(natsDialTimeout),
		nats.PingInterval(natsPingInterval),
		nats.MaxReconnects(natsMaxReconnect),
		nats.ReconnectWait(natsReconnectWait),
	}
	if len(natsCAPath) > 0 {
		options = append(options, nats.RootCAs(natsCAPath...))
	}
	if len(natsClientCertFile) > 0 && len(natsClientKeyFile) > 0 {
		options = append(options, nats.ClientCert(natsClientCertFile, natsClientKeyFile))
	}
	if len(natsUser) > 0 || len(natsPass) > 0 {
		options = append(options, nats.UserInfo(natsUser, natsPass))
	}

	conn, err := nats.Connect(natsURL, options...)
	if err != nil {
		return nil, err
	}
	return &natsState{
		conn:    conn,
		subject: natsSubject,
		l:       logger,
	}, nil
}
