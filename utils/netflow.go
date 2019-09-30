package utils

import (
	"bytes"
	"encoding/json"
	"github.com/cloudflare/goflow/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/pb"
	"github.com/cloudflare/goflow/producer"
	"github.com/prometheus/client_golang/prometheus"
	"net/http"
	"strconv"
	"sync"
	"time"
)

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

type StateNetFlow struct {
	Transport     Transport
	Logger        Logger
	templateslock *sync.RWMutex
	templates     map[string]*TemplateSystem

	samplinglock *sync.RWMutex
	sampling     map[string]producer.SamplingRateSystem
}

func (s *StateNetFlow) DecodeFlow(msg interface{}) error {
	pkt := msg.(BaseMessage)
	buf := bytes.NewBuffer(pkt.Payload)

	key := pkt.Src.String()
	samplerAddress := pkt.Src
	if samplerAddress.To4() != nil {
		samplerAddress = samplerAddress.To4()
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
			fmsg.TimeReceived = uint64(time.Now().UTC().Unix())
			fmsg.SamplerAddress = samplerAddress
			timeDiff := fmsg.TimeReceived - fmsg.TimeFlowEnd
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
						"type":    "TemplateFlowSet",
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
			fmsg.TimeReceived = uint64(time.Now().UTC().Unix())
			fmsg.SamplerAddress = samplerAddress
			timeDiff := fmsg.TimeReceived - fmsg.TimeFlowEnd
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

	if s.Transport != nil {
		s.Transport.Publish(flowMessageSet)
	}

	return nil
}

func (s *StateNetFlow) ServeHTTPTemplates(w http.ResponseWriter, r *http.Request) {
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

func (s *StateNetFlow) InitTemplates() {
	s.templates = make(map[string]*TemplateSystem)
	s.templateslock = &sync.RWMutex{}
	s.sampling = make(map[string]producer.SamplingRateSystem)
	s.samplinglock = &sync.RWMutex{}
}

func (s *StateNetFlow) FlowRoutine(workers int, addr string, port int, reuseport bool) error {
	s.InitTemplates()
	return UDPRoutine("NetFlow", s.DecodeFlow, workers, addr, port, reuseport, s.Logger)
}
