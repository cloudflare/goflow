package main

import (
	"flag"
	"fmt"
	"github.com/cloudflare/goflow/transport"
	"github.com/cloudflare/goflow/utils"
	log "github.com/sirupsen/logrus"
	"os"
	"runtime"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "GoFlow NetFlow " + version + " " + buildinfos

	Addr  = flag.String("addr", "", "NetFlow/IPFIX listening address")
	Port  = flag.Int("port", 2055, "NetFlow/IPFIX listening port")
	Reuse = flag.Bool("reuse", false, "Enable so_reuseport for NetFlow/IPFIX listening port")

	Workers  = flag.Int("workers", 1, "Number of NetFlow workers")
	LogLevel = flag.String("loglevel", "info", "Log level")
	LogFmt   = flag.String("logfmt", "normal", "Log formatter")

	EnableKafka  = flag.Bool("kafka", true, "Enable Kafka")
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
	switch *LogFmt {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	log.Info("Starting GoFlow")

	s := &utils.StateNetFlow{
		Transport: &utils.DefaultLogTransport{},
		Logger:    log.StandardLogger(),
	}

	go httpServer(s)

	if *EnableKafka {
		kafkaState, err := transport.StartKafkaProducerFromArgs(log.StandardLogger())
		if err != nil {
			log.Fatal(err)
		}
		s.Transport = kafkaState
	}
	log.WithFields(log.Fields{
		"Type": "NetFlow"}).
		Infof("Listening on UDP %v:%v", *Addr, *Port)

	err := s.FlowRoutine(*Workers, *Addr, *Port, *Reuse)
	if err != nil {
		log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
	}
}
