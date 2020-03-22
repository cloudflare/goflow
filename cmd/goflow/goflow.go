package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sync"

	"github.com/cloudflare/goflow/v3/transport"
	"github.com/cloudflare/goflow/v3/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
)

var (
	version    = ""
	buildinfos = ""
	AppVersion = "GoFlow " + version + " " + buildinfos

	SFlowEnable = flag.Bool("sflow", true, "Enable sFlow")
	SFlowAddr   = flag.String("sflow.addr", "", "sFlow listening address")
	SFlowPort   = flag.Int("sflow.port", 6343, "sFlow listening port")
	SFlowReuse  = flag.Bool("sflow.reuserport", false, "Enable so_reuseport for sFlow")

	NFLEnable = flag.Bool("nfl", true, "Enable NetFlow v5")
	NFLAddr   = flag.String("nfl.addr", "", "NetFlow v5 listening address")
	NFLPort   = flag.Int("nfl.port", 2056, "NetFlow v5 listening port")
	NFLReuse  = flag.Bool("nfl.reuserport", false, "Enable so_reuseport for NetFlow v5")

	NFEnable = flag.Bool("nf", true, "Enable NetFlow/IPFIX")
	NFAddr   = flag.String("nf.addr", "", "NetFlow/IPFIX listening address")
	NFPort   = flag.Int("nf.port", 2055, "NetFlow/IPFIX listening port")
	NFReuse  = flag.Bool("nf.reuserport", false, "Enable so_reuseport for NetFlow/IPFIX")

	Workers  = flag.Int("workers", 1, "Number of workers per collector")
	LogLevel = flag.String("loglevel", "info", "Log level")
	LogFmt   = flag.String("logfmt", "normal", "Log formatter")

	EnableKafka = flag.Bool("kafka", true, "Enable Kafka")
	FixedLength = flag.Bool("proto.fixedlen", false, "Enable fixed length protobuf")
	MetricsAddr = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath = flag.String("metrics.path", "/metrics", "Metrics path")

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

	sSFlow := &utils.StateSFlow{
		Transport: defaultTransport,
		Logger:    log.StandardLogger(),
	}
	sNF := &utils.StateNetFlow{
		Transport: defaultTransport,
		Logger:    log.StandardLogger(),
	}
	sNFL := &utils.StateNFLegacy{
		Transport: defaultTransport,
		Logger:    log.StandardLogger(),
	}

	go httpServer(sNF)

	if *EnableKafka {
		kafkaState, err := transport.StartKafkaProducerFromArgs(log.StandardLogger())
		if err != nil {
			log.Fatal(err)
		}
		kafkaState.FixedLengthProto = *FixedLength

		sSFlow.Transport = kafkaState
		sNFL.Transport = kafkaState
		sNF.Transport = kafkaState
	}

	wg := &sync.WaitGroup{}
	if *SFlowEnable {
		wg.Add(1)
		go func() {
			log.WithFields(log.Fields{
				"Type": "sFlow"}).
				Infof("Listening on UDP %v:%v", *SFlowAddr, *SFlowPort)

			err := sSFlow.FlowRoutine(*Workers, *SFlowAddr, *SFlowPort, *SFlowReuse)
			if err != nil {
				log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
			}
			wg.Done()
		}()
	}
	if *NFEnable {
		wg.Add(1)
		go func() {
			log.WithFields(log.Fields{
				"Type": "NetFlow"}).
				Infof("Listening on UDP %v:%v", *NFAddr, *NFPort)

			err := sNF.FlowRoutine(*Workers, *NFAddr, *NFPort, *NFReuse)
			if err != nil {
				log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
			}
			wg.Done()
		}()
	}
	if *NFLEnable {
		wg.Add(1)
		go func() {
			log.WithFields(log.Fields{
				"Type": "NetFlowLegacy"}).
				Infof("Listening on UDP %v:%v", *NFLAddr, *NFLPort)

			err := sNFL.FlowRoutine(*Workers, *NFLAddr, *NFLPort, *NFLReuse)
			if err != nil {
				log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
			}
			wg.Done()
		}()
	}
	wg.Wait()
}
