package utils

import (
	"bytes"
	"net"
	"time"

	"github.com/cloudflare/goflow/v3/decoders/sflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
	"github.com/cloudflare/goflow/v3/producer"
	"github.com/prometheus/client_golang/prometheus"
)

type StateSFlow struct {
	Transport Transport
	Logger    Logger

	Config *producer.SFlowProducerConfig
}

func (s *StateSFlow) DecodeFlow(msg interface{}) error {
	pkt := msg.(BaseMessage)
	buf := bytes.NewBuffer(pkt.Payload)
	key := pkt.Src.String()

	ts := uint64(time.Now().UTC().Unix())
	if pkt.SetTime {
		ts = uint64(pkt.RecvTime.UTC().Unix())
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
	flowMessageSet, err = producer.ProcessMessageSFlowConfig(msgDec, s.Config)

	timeTrackStop := time.Now()
	DecoderTime.With(
		prometheus.Labels{
			"name": "sFlow",
		}).
		Observe(float64((timeTrackStop.Sub(timeTrackStart)).Nanoseconds()) / 1000)

	for _, fmsg := range flowMessageSet {
		fmsg.TimeReceived = ts
		fmsg.TimeFlowStart = ts
		fmsg.TimeFlowEnd = ts
	}

	if s.Transport != nil {
		s.Transport.Publish(flowMessageSet)
	}

	return nil
}

func (s *StateSFlow) FlowRoutine(workers int, addr string, port int, reuseport bool) error {
	return UDPRoutine("sFlow", s.DecodeFlow, workers, addr, port, reuseport, s.Logger)
}
