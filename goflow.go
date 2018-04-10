package main

import (
	"errors"
	"flag"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/cloudflare/goflow/decoders"
	"github.com/cloudflare/goflow/decoders/netflow"
	"github.com/cloudflare/goflow/decoders/sflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/cloudflare/goflow/producer"
	"github.com/cloudflare/goflow/transport"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"

	"encoding/json"

	"bytes"
)

const AppVersion = "GoFlow v2.0.0"

var (
	FEnable = flag.Bool("netflow", true, "Enable NetFlow")
	SEnable = flag.Bool("sflow", true, "Enable sFlow")

	FAddr = flag.String("faddr", ":", "NetFlow/IPFIX listening address")
	FPort = flag.Int("fport", 2055, "NetFlow/IPFIX listening port")

	SAddr = flag.String("saddr", ":", "sFlow listening address")
	SPort = flag.Int("sport", 6343, "sFlow listening port")

	FWorkers = flag.Int("fworkers", 1, "Number of NetFlow workers")
	SWorkers = flag.Int("sworkers", 1, "Number of sFlow workers")
	LogLevel = flag.String("loglevel", "info", "Log level")
	LogFmt   = flag.String("logfmt", "normal", "Log formatter")

	EnableKafka  = flag.Bool("kafka", true, "Enable Kafka")
	MetricsAddr  = flag.String("metrics.addr", ":8080", "Metrics address")
	MetricsPath  = flag.String("metrics.path", "/metrics", "Metrics path")
	TemplatePath = flag.String("templates.path", "/templates", "NetFlow/IPFIX templates list")

	KafkaTopic = flag.String("kafka.out.topic", "flow-messages", "Kafka topic to produce to")
	KafkaSrv   = flag.String("kafka.out.srv", "", "SRV record containing a list of Kafka brokers (or use kafka.out.brokers)")
	KafkaBrk   = flag.String("kafka.out.brokers", "127.0.0.1:9092,[::1]:9092", "Kafka brokers list separated by commas")

	Version = flag.Bool("v", false, "Print version")
)

func init() {
	initMetrics()
}

func metricsHTTP() {
	http.Handle(*MetricsPath, promhttp.Handler())
	log.Fatal(http.ListenAndServe(*MetricsAddr, nil))
}

func templatesHTTP(s *state) {
	http.Handle(*TemplatePath, s)
}

func (s *state) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tmp := make(map[string]map[uint16]map[uint32]map[uint16]interface{})
	s.templateslock.RLock()
	for key, templatesrouterstr := range s.templates {
		templatesrouter := templatesrouterstr.templates.GetTemplates()
		tmp[key] = templatesrouter
	}
	s.templateslock.RUnlock()
	enc := json.NewEncoder(w)
	enc.Encode(tmp)
}

type TemplateSystem struct {
	key       string
	templates *netflow.BasicTemplateSystem
}

func (s *TemplateSystem) AddTemplate(version uint16, obsDomainId uint32, template interface{}) {
	s.templates.AddTemplate(version, obsDomainId, template)

	typeStr := "options_template"
	var templateId uint16
	switch templateIdConv := template.(type) {
	case netflow.IPFIXOptionsTemplateRecord:
		templateId = templateIdConv.TemplateId
	case netflow.NFv9OptionsTemplateRecord:
		templateId = templateIdConv.TemplateId
	case netflow.TemplateRecord:
		templateId = templateIdConv.TemplateId
		typeStr = "template"
	}
	NetFlowTemplatesStats.With(
		prometheus.Labels{
			"router":        s.key,
			"version":       strconv.Itoa(int(version)),
			"obs_domain_id": strconv.Itoa(int(obsDomainId)),
			"template_id":   strconv.Itoa(int(templateId)),
			"type":          typeStr,
		}).
		Inc()
}

func (s *TemplateSystem) GetTemplate(version uint16, obsDomainId uint32, templateId uint16) (interface{}, error) {
	return s.templates.GetTemplate(version, obsDomainId, templateId)
}

func (s *state) decodeNetFlow(msg interface{}) error {
	pkt := msg.(BaseMessage)
	buf := bytes.NewBuffer(pkt.Payload)

	key := pkt.Src.String()
	routerAddr := pkt.Src
	if routerAddr.To4() != nil {
		routerAddr = routerAddr.To4()
	}

	s.templateslock.RLock()
	templates, ok := s.templates[key]
	if !ok {
		templates = &TemplateSystem{
			templates: netflow.CreateTemplateSystem(),
			key:       key,
		}
		s.templates[key] = templates
	}
	s.templateslock.RUnlock()
	s.samplinglock.RLock()
	sampling, ok := s.sampling[key]
	if !ok {
		sampling = producer.CreateSamplingSystem()
		s.sampling[key] = sampling
	}
	s.samplinglock.RUnlock()

	timeTrackStart := time.Now()
	msgDec, err := netflow.DecodeMessage(buf, templates)
	if err != nil {
		switch err.(type) {
		case *netflow.ErrorVersion:
			NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_version",
				}).
				Inc()
		case *netflow.ErrorFlowId:
			NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_flow_id",
				}).
				Inc()
		case *netflow.ErrorTemplateNotFound:
			NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "template_not_found",
				}).
				Inc()
		default:
			NetFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_decoding",
				}).
				Inc()
		}
		return err
	}

	flowMessageSet := make([]*flowmessage.FlowMessage, 0)

	switch msgDecConv := msgDec.(type) {
	case netflow.NFv9Packet:
		NetFlowStats.With(
			prometheus.Labels{
				"router":  key,
				"version": "9",
			}).
			Inc()

		for _, fs := range msgDecConv.FlowSets {
			switch fsConv := fs.(type) {
			case netflow.TemplateFlowSet:
				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "TemplateFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsTemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.NFv9OptionsTemplateFlowSet:
				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsTemplateFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsTemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.OptionsDataFlowSet:
				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsDataFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "OptionsDataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))
			case netflow.DataFlowSet:
				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "DataFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "9",
						"type":    "DataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))
			}
		}
		flowMessageSet, err = producer.ProcessMessageNetFlow(msgDecConv, sampling)

		for _, fmsg := range flowMessageSet {
			fmsg.TimeRecvd = uint64(time.Now().UTC().Unix())
			fmsg.RouterAddr = routerAddr
			timeDiff := fmsg.TimeRecvd - fmsg.TimeFlow
			NetFlowTimeStatsSum.With(
				prometheus.Labels{
					"router":  key,
					"version": "9",
				}).
				Observe(float64(timeDiff))
		}
	case netflow.IPFIXPacket:
		NetFlowStats.With(
			prometheus.Labels{
				"router":  key,
				"version": "10",
			}).
			Inc()

		for _, fs := range msgDecConv.FlowSets {
			switch fsConv := fs.(type) {
			case netflow.TemplateFlowSet:
				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "TemplateFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsTemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.IPFIXOptionsTemplateFlowSet:
				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsTemplateFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsTemplateFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.OptionsDataFlowSet:

				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsDataFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "OptionsDataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))

			case netflow.DataFlowSet:
				NetFlowSetStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "DataFlowSet",
					}).
					Inc()

				NetFlowSetRecordsStatsSum.With(
					prometheus.Labels{
						"router":  key,
						"version": "10",
						"type":    "DataFlowSet",
					}).
					Add(float64(len(fsConv.Records)))
			}
		}
		flowMessageSet, err = producer.ProcessMessageNetFlow(msgDecConv, sampling)

		for _, fmsg := range flowMessageSet {
			fmsg.TimeRecvd = uint64(time.Now().UTC().Unix())
			fmsg.RouterAddr = routerAddr
			timeDiff := fmsg.TimeRecvd - fmsg.TimeFlow
			NetFlowTimeStatsSum.With(
				prometheus.Labels{
					"router":  key,
					"version": "10",
				}).
				Observe(float64(timeDiff))
		}
	}

	timeTrackStop := time.Now()
	DecoderTime.With(
		prometheus.Labels{
			"name": "NetFlow",
		}).
		Observe(float64((timeTrackStop.Sub(timeTrackStart)).Nanoseconds()) / 1000)

	s.produceFlow(flowMessageSet)

	return nil
}

func (s *state) produceFlow(fmsgset []*flowmessage.FlowMessage) {
	for _, fmsg := range fmsgset {
		if s.kafkaEn {
			s.kafkaState.SendKafkaFlowMessage(fmsg)
		}
		if s.debug {
			log.Debugf("Packet received: %v", fmsg)
		}
	}

}

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte
}

func (s *state) netflowRoutine() {
	go templatesHTTP(s)

	s.templates = make(map[string]*TemplateSystem)
	s.templateslock = &sync.RWMutex{}
	s.sampling = make(map[string]producer.SamplingRateSystem)
	s.samplinglock = &sync.RWMutex{}

	decoderParams := decoder.DecoderParams{
		DecoderFunc:   s.decodeNetFlow,
		DoneCallback:  s.accountCallback,
		ErrorCallback: nil,
	}
	log.Infof("Creating NetFlow message processor with %v workers", s.fworkers)
	processor := decoder.CreateProcessor(s.fworkers, decoderParams, "NetFlow")
	log.WithFields(log.Fields{
		"Name": "NetFlow"}).Debug("Starting workers")
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

		baseMessage := BaseMessage{
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

func (s *state) decodeSflow(msg interface{}) error {
	pkt := msg.(BaseMessage)
	buf := bytes.NewBuffer(pkt.Payload)
	key := pkt.Src.String()
	routerAddr := pkt.Src
	if routerAddr.To4() != nil {
		routerAddr = routerAddr.To4()
	}

	timeTrackStart := time.Now()
	msgDec, err := sflow.DecodeMessage(buf)

	if err != nil {
		switch err.(type) {
		case *sflow.ErrorVersion:
			SFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_version",
				}).
				Inc()
		case *sflow.ErrorIPVersion:
			SFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_ip_version",
				}).
				Inc()
		case *sflow.ErrorDataFormat:
			SFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_data_format",
				}).
				Inc()
		default:
			SFlowErrors.With(
				prometheus.Labels{
					"router": key,
					"error":  "error_decoding",
				}).
				Inc()
		}
		return err
	}

	switch msgDecConv := msgDec.(type) {
	case sflow.Packet:
		agentStr := net.IP(msgDecConv.AgentIP).String()
		SFlowStats.With(
			prometheus.Labels{
				"router":  key,
				"agent":   agentStr,
				"version": "5",
			}).
			Inc()

		for _, samples := range msgDecConv.Samples {
			typeStr := "unknown"
			countRec := 0
			switch samplesConv := samples.(type) {
			case sflow.FlowSample:
				typeStr = "FlowSample"
				countRec = len(samplesConv.Records)
			case sflow.CounterSample:
				typeStr = "CounterSample"
				if samplesConv.Header.Format == 4 {
					typeStr = "Expanded" + typeStr
				}
				countRec = len(samplesConv.Records)
			case sflow.ExpandedFlowSample:
				typeStr = "ExpandedFlowSample"
				countRec = len(samplesConv.Records)
			}
			SFlowSampleStatsSum.With(
				prometheus.Labels{
					"router":  key,
					"agent":   agentStr,
					"version": "5",
					"type":    typeStr,
				}).
				Inc()

			SFlowSampleRecordsStatsSum.With(
				prometheus.Labels{
					"router":  key,
					"agent":   agentStr,
					"version": "5",
					"type":    typeStr,
				}).
				Add(float64(countRec))
		}

	}

	var flowMessageSet []*flowmessage.FlowMessage
	flowMessageSet, err = producer.ProcessMessageSFlow(msgDec)

	timeTrackStop := time.Now()
	DecoderTime.With(
		prometheus.Labels{
			"name": "sFlow",
		}).
		Observe(float64((timeTrackStop.Sub(timeTrackStart)).Nanoseconds()) / 1000)

	ts := uint64(time.Now().UTC().Unix())
	for _, fmsg := range flowMessageSet {
		fmsg.TimeRecvd = ts
		fmsg.TimeFlow = ts
		fmsg.RouterAddr = routerAddr
	}

	s.produceFlow(flowMessageSet)

	return nil
}

func (s *state) accountCallback(name string, id int, start, end time.Time) {
	DecoderProcessTime.With(
		prometheus.Labels{
			"name": name,
		}).
		Observe(float64((end.Sub(start)).Nanoseconds()) / 1000)
	DecoderStats.With(
		prometheus.Labels{
			"worker": strconv.Itoa(id),
			"name":   name,
		}).
		Inc()
}

type state struct {
	kafkaState *transport.KafkaState
	kafkaEn    bool

	templateslock *sync.RWMutex
	templates     map[string]*TemplateSystem

	samplinglock *sync.RWMutex
	sampling     map[string]producer.SamplingRateSystem

	debug bool

	fworkers int
	sworkers int
}

func (s *state) sflowRoutine() {
	decoderParams := decoder.DecoderParams{
		DecoderFunc:   s.decodeSflow,
		DoneCallback:  s.accountCallback,
		ErrorCallback: nil,
	}

	processor := decoder.CreateProcessor(s.sworkers, decoderParams, "sFlow")
	log.WithFields(log.Fields{
		"Name": "sFlow"}).Debug("Starting workers")
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

		baseMessage := BaseMessage{
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

func GetServiceAddresses(srv string) (addrs []string, err error) {
	_, srvs, err := net.LookupSRV("", "", srv)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Service discovery: %v\n", err))
	}
	for _, srv := range srvs {
		addrs = append(addrs, net.JoinHostPort(srv.Target, strconv.Itoa(int(srv.Port))))
	}
	return addrs, nil
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

	s := &state{
		fworkers: *FWorkers,
		sworkers: *SWorkers,
	}

	if *LogLevel == "debug" {
		s.debug = true
	}

	if *EnableKafka {
		addrs := make([]string, 0)
		if *KafkaSrv != "" {
			addrs, _ = GetServiceAddresses(*KafkaSrv)
		} else {
			addrs = strings.Split(*KafkaBrk, ",")
		}
		kafkaState := transport.StartKafkaProducer(addrs, *KafkaTopic)
		s.kafkaState = kafkaState
		s.kafkaEn = true
	}

	if *FEnable {
		(*wg).Add(1)
		go func() {
			s.netflowRoutine()
			(*wg).Done()
		}()
	}
	if *SEnable {
		(*wg).Add(1)
		go func() {
			s.sflowRoutine()
			(*wg).Done()
		}()
	}

	(*wg).Wait()
}
