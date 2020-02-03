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
	AppVersion = "Go-nProbe " + version + " " + buildinfos

	Addr  = flag.String("addr", "", "NetFlow/IPFIX listening address")
	Port  = flag.Int("port", 2055, "NetFlow/IPFIX listening port")
	Reuse = flag.Bool("reuse", false, "Enable so_reuseport for NetFlow/IPFIX listening port")

	MetricsAddr  = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath  = flag.String("metrics.path", "/metrics", "Metrics path")
	TemplatePath = flag.String("templates.path", "/templates", "NetFlow/IPFIX templates list")

	Workers  = flag.Int("workers", 1, "Number of NetFlow workers")
	LogLevel = flag.String("loglevel", "info", "Log level")
	LogFmt   = flag.String("logfmt", "normal", "Log formatter: {normal|json}")

	Version = flag.Bool("v", false, "Print version")
)

func init() {
	transport.RegisterZmqFlags()
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

	log.Info("Starting Go-nProbe")

	s := &utils.StateNetFlow{
		Transport: defaultTransport,
		Logger:    log.StandardLogger(),
	}

	go httpServer(s)

	zmqState, err := transport.StartZmqProducerFromArgs(log.StandardLogger())
	if err != nil {
		log.Fatal(err)
	}
	s.Transport = zmqState

	log.WithFields(log.Fields{
		"Type": "NetFlow"}).
		Infof("Listening on UDP %v:%v", *Addr, *Port)

	err = s.FlowRoutine(*Workers, *Addr, *Port, *Reuse)
	if err != nil {
		log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
	}
}
