package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"

	"github.com/cloudflare/goflow/v3/transport"
	"github.com/cloudflare/goflow/v3/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "GoFlow NetFlow " + version + " " + buildinfos

	Addr  = flag.String("addr", "", "NetFlow/IPFIX listening address")
	Port  = flag.Int("port", 2055, "NetFlow/IPFIX listening port")
	Reuse = flag.Int("reuse", 0, "Enable so_reuseport for NetFlow/IPFIX listening port")

	Workers  = flag.Int("workers", 1, "Number of NetFlow workers")
	LogLevel = flag.String("loglevel", "info", "Log level")
	LogFmt   = flag.String("logfmt", "normal", "Log formatter")

	EnableKafka  = flag.Bool("kafka", true, "Enable Kafka")
	FixedLength  = flag.Bool("proto.fixedlen", false, "Enable fixed length protobuf")
	MetricsAddr  = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath  = flag.String("metrics.path", "/metrics", "Metrics path")
	TemplatePath = flag.String("templates.path", "/templates", "NetFlow/IPFIX templates list")

	Version = flag.Bool("v", false, "Print version")
)

func init() {
	transport.RegisterFlags()
}

func httpServer(state *utils.StateNetFlow) {
	http.Handle(*MetricsPath, promhttp.Handler())
	http.HandleFunc(*TemplatePath, state.ServeHTTPTemplates)
	log.Fatal(http.ListenAndServe(*MetricsAddr, nil))
}

func main() {
	flag.Parse()

	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)

	var defaultTransport utils.Transport
	defaultTransport = &utils.DefaultLogTransport{}

	switch *LogFmt {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
		defaultTransport = &utils.DefaultJSONTransport{}
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Info("Starting GoFlow")

	s := &utils.StateNetFlow{
		Transport: defaultTransport,
		Logger:    log.StandardLogger(),
	}

	go httpServer(s)

	if *EnableKafka {
		kafkaState, err := transport.StartKafkaProducerFromArgs(log.StandardLogger())
		if err != nil {
			log.Fatal(err)
		}
		kafkaState.FixedLengthProto = *FixedLength
		s.Transport = kafkaState
	}
	log.WithFields(log.Fields{
		"Type": "NetFlow"}).
		Infof("Listening on UDP %s:%d (reuse: %d, workers: %d)", *Addr, *Port, *Reuse, *Workers)

	err := s.FlowRoutine(*Workers, *Addr, *Port, *Reuse)
	if err != nil {
		log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
	}
}
