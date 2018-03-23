package producer

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync"
)

type ProcessArguments struct {
	KafkaState *KafkaState

	SamplingRateMap   SamplingRateMap
	SamplingRateLock  *sync.RWMutex
	SamplingRateFixed int

	TemplateMap     TemplateMap
	TemplateMapLock *sync.RWMutex

	UniqueTemplates bool
}

func CreateProcessArguments(kafka bool, samplingRate int, uniqueTemplates bool) ProcessArguments {
	prometheus.MustRegister(NetFlowStats)
	prometheus.MustRegister(NetFlowErrors)
	prometheus.MustRegister(NetFlowSetRecordsStatsSum)
	prometheus.MustRegister(NetFlowSetStatsSum)
	prometheus.MustRegister(NetFlowTimeStatsSum)
	prometheus.MustRegister(NetFlowTemplatesStats)

	prometheus.MustRegister(SFlowStats)
	prometheus.MustRegister(SFlowErrors)
	prometheus.MustRegister(SFlowSampleStatsSum)
	prometheus.MustRegister(SFlowSampleRecordsStatsSum)

	var kafkaState *KafkaState
	if kafka {
		kafkaState = StartKafkaProducer()
	}

	processArgs := ProcessArguments{
		KafkaState:        kafkaState,
		SamplingRateMap:   make(map[string]map[uint32]uint64),
		SamplingRateLock:  &sync.RWMutex{},
		TemplateMap:       make(map[string]map[uint32]map[uint16]bool),
		TemplateMapLock:   &sync.RWMutex{},
		SamplingRateFixed: samplingRate,
		UniqueTemplates:   uniqueTemplates,
	}
	return processArgs
}
