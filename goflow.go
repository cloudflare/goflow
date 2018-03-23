package main

import (
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/cloudflare/goflow/decoders/netflow"
	"github.com/cloudflare/goflow/decoders/sflow"
	"github.com/cloudflare/goflow/producer"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"

	"encoding/json"
)

const AppVersion = "GoFlow v1.1.0"

var (
	FEnable = flag.Bool("netflow", true, "Enable NetFlow")
	SEnable = flag.Bool("sflow", true, "Enable sFlow")

	FAddr = flag.String("faddr", ":", "NetFlow/IPFIX listening address")
	FPort = flag.Int("fport", 2055, "NetFlow/IPFIX listening port")

	SAddr = flag.String("saddr", ":", "sFlow listening address")
	SPort = flag.Int("sport", 6343, "sFlow listening port")

	SamplingRate = flag.Int("sampling", 16834, "Fixed NetFlow sampling rate (-1 to disable)")
	FWorkers     = flag.Int("fworkers", 1, "Number of NetFlow workers")
	SWorkers     = flag.Int("sworkers", 1, "Number of sFlow workers")
	LogLevel     = flag.String("loglevel", "info", "Log level")
	LogFmt       = flag.String("logfmt", "normal", "Log formatter")

	EnableKafka     = flag.Bool("kafka", true, "Enable Kafka")
	UniqueTemplates = flag.Bool("uniquetemplates", false, "Unique templates (vs per-router/obs domain id) ; must have same sampling rate everywhere)")
	MetricsAddr     = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath     = flag.String("metrics.path", "/metrics", "Metrics path")
	TemplatePath    = flag.String("templates.path", "/templates", "NetFlow/IPFIX templates list")

	Version = flag.Bool("v", false, "Print version")

	MetricTrafficBytes = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_traffic_bytes",
			Help: "Bytes received by the application.",
		},
		[]string{"remote_ip", "remote_port", "local_ip", "local_port", "type"},
	)
	MetricTrafficPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_traffic_packets",
			Help: "Packets received by the application.",
		},
		[]string{"remote_ip", "remote_port", "local_ip", "local_port", "type"},
	)
	MetricPacketSizeSum = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "flow_traffic_summary_size_bytes",
			Help:       "Summary of packet size.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"remote_ip", "remote_port", "local_ip", "local_port", "type"},
	)
)

func init() {
	prometheus.MustRegister(MetricTrafficBytes)
	prometheus.MustRegister(MetricTrafficPackets)
	prometheus.MustRegister(MetricPacketSizeSum)
}

func metricsHTTP() {
	http.Handle(*MetricsPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(*MetricsAddr, nil))
}

func templatesHTTP(th TemplateHandler) {
	http.Handle(*TemplatePath, th)
}

type TemplateHandler struct {
	Config *netflow.DecoderConfig
}

func (h TemplateHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if h.Config != nil {
		h.Config.NetFlowV9TemplateSetLock.RLock()
		h.Config.IPFIXTemplateSetLock.RLock()

		templates := make([]map[string]map[uint32]map[uint16][]netflow.Field, 2)
		templates[0] = h.Config.NetFlowV9TemplateSet
		templates[1] = h.Config.IPFIXTemplateSet

		enc := json.NewEncoder(w)
		enc.Encode(templates)

		h.Config.IPFIXTemplateSetLock.RUnlock()
		h.Config.NetFlowV9TemplateSetLock.RUnlock()
	} else {
		log.Debugf("No config found")
	}
}

func netflowRoutine(processArgs *producer.ProcessArguments, wg *sync.WaitGroup) {
	defer (*wg).Done()

	nfConfig := netflow.CreateConfig()
	nfConfig.UniqueTemplates = *UniqueTemplates

	th := TemplateHandler{}
	th.Config = &nfConfig
	go templatesHTTP(th)

	processor := netflow.CreateProcessor(*FWorkers, nfConfig, producer.ProcessMessageNetFlow, *processArgs, producer.ProcessNetFlowError)
	processor.Start()

	addr := net.UDPAddr{
		IP:   net.ParseIP(*FAddr),
		Port: *FPort,
	}
	udpconn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
		udpconn.Close()
	}

	payload := make([]byte, 9000)

	localIP := addr.IP.String()
	if addr.IP == nil {
		localIP = ""
	}
	log.WithFields(log.Fields{
		"Type": "NetFlow"}).
		Infof("Listening on UDP %v:%v", localIP, strconv.Itoa(addr.Port))
	for {
		size, pktAddr, _ := udpconn.ReadFromUDP(payload)
		payloadCut := make([]byte, size)
		copy(payloadCut, payload[0:size])

		baseMessage := netflow.BaseMessage{
			Src:     pktAddr.IP,
			Port:    pktAddr.Port,
			Payload: payloadCut,
		}
		processor.ProcessMessage(baseMessage)

		MetricTrafficBytes.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addr.Port),
				"type":        "NetFlow",
			}).
			Add(float64(size))
		MetricTrafficPackets.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addr.Port),
				"type":        "NetFlow",
			}).
			Inc()
		MetricPacketSizeSum.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addr.Port),
				"type":        "NetFlow",
			}).
			Observe(float64(size))
	}

	udpconn.Close()
}

func sflowRoutine(processArgs *producer.ProcessArguments, wg *sync.WaitGroup) {
	defer (*wg).Done()

	sfConfig := sflow.CreateConfig()

	processor := sflow.CreateProcessor(*SWorkers, sfConfig, producer.ProcessMessageSFlow, *processArgs, producer.ProcessSFlowError)
	processor.Start()

	addr := net.UDPAddr{
		IP:   net.ParseIP(*SAddr),
		Port: *SPort,
	}
	udpconn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Fatal error: could not listen to UDP (%v)", err)
		udpconn.Close()
	}

	payload := make([]byte, 9000)

	localIP := addr.IP.String()
	if addr.IP == nil {
		localIP = ""
	}
	log.WithFields(log.Fields{
		"Type": "sFlow"}).
		Infof("Listening on UDP %v:%v", localIP, strconv.Itoa(addr.Port))
	for {
		size, pktAddr, _ := udpconn.ReadFromUDP(payload)
		payloadCut := make([]byte, size)
		copy(payloadCut, payload[0:size])

		baseMessage := sflow.BaseMessage{
			Src:     pktAddr.IP,
			Port:    pktAddr.Port,
			Payload: payloadCut,
		}
		processor.ProcessMessage(baseMessage)

		MetricTrafficBytes.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addr.Port),
				"type":        "sFlow",
			}).
			Add(float64(size))
		MetricTrafficPackets.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addr.Port),
				"type":        "sFlow",
			}).
			Inc()
		MetricPacketSizeSum.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addr.Port),
				"type":        "sFlow",
			}).
			Observe(float64(size))
	}

	udpconn.Close()
}

func main() {
	flag.Parse()

	if *Version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	go metricsHTTP()

	lvl, _ := log.ParseLevel(*LogLevel)
	log.SetLevel(lvl)
	switch *LogFmt {
	case "json":
		log.SetFormatter(&log.JSONFormatter{})
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	wg := &sync.WaitGroup{}
	log.WithFields(log.Fields{
		"NetFlow": *FEnable,
		"sFlow":   *SEnable}).
		Info("Starting GoFlow")

	processArgs := producer.CreateProcessArguments(*EnableKafka, *SamplingRate, *UniqueTemplates)

	if *FEnable {
		(*wg).Add(1)
		go netflowRoutine(&processArgs, wg)
	}
	if *SEnable {
		(*wg).Add(1)
		go sflowRoutine(&processArgs, wg)
	}

	(*wg).Wait()
}
