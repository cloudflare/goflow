package decoder

import (
	log "github.com/Sirupsen/logrus"
	"github.com/prometheus/client_golang/prometheus"
	"strconv"
	"sync"
	"time"
)

type Message interface{}
type MessageDecoded interface{}
type DecoderConfig interface{}
type CallbackArgs interface{}

type DecoderFunc func(Message, DecoderConfig) (MessageDecoded, error)
type DoneCallback func(interface{}, interface{}, interface{}) (bool, error)
type ErrorCallback func(interface{}, error, interface{}, interface{}) (bool, error)

//type DoneCallback   func(MessageDecoded, DoneCallbackConfig) (bool, error)

var (
	MetricsRegistered       bool
	MetricsRegistrationLock = &sync.Mutex{}

	DecoderStats = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_decoder_count",
			Help: "Decoder processed count.",
		},
		[]string{"worker", "name"},
	)
	DecoderErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "flow_decoder_error_count",
			Help: "Decoder processed error count.",
		},
		[]string{"worker", "name"},
	)
	DecoderTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "flow_summary_decoding_time_us",
			Help:       "Decoding time summary.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"name"},
	)
	DecoderProcessTime = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name:       "flow_summary_processing_time_us",
			Help:       "Processing time summary.",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
		[]string{"name"},
	)
)

// Worker structure
type Worker struct {
	Id            int
	DecoderParams DecoderParams
	WorkerPool    chan chan Message
	Name          string
	InMsg         chan Message
	Quit          chan bool
}

// Create a worker and add it to the pool.
func CreateWorker(workerPool chan chan Message, decoderParams DecoderParams, id int, name string) Worker {
	return Worker{
		Id:            id,
		DecoderParams: decoderParams,
		WorkerPool:    workerPool,
		Name:          name,
		InMsg:         make(chan Message),
		Quit:          make(chan bool),
	}
}

// Start the worker. Launches a goroutine to process NFv9 messages.
// The worker will add its input channel of NFv9 messages to decode to the pool.
func (w Worker) Start() {
	go func() {
		log.Debugf("Worker %v started", w.Id)
		for {
			w.WorkerPool <- w.InMsg
			select {
			case <-w.Quit:
				break
			case msg := <-w.InMsg:
				//log.Printf("Worker %v: Received msg\n", w.Id)
				timeTrackStart := time.Now()
				msgdec, err := w.DecoderParams.DecoderFunc(msg, w.DecoderParams.DecoderConfig)
				timeTrackStop := time.Now()
				DecoderTime.With(
					prometheus.Labels{
						"name": w.Name,
					}).
					Observe(float64((timeTrackStop.Sub(timeTrackStart)).Nanoseconds()) / 1000)

				if err != nil {
					//fmt.Printf("Worker %v: error: %v\n", w.Id, err)
					if w.DecoderParams.ErrorCallback != nil {
						w.DecoderParams.ErrorCallback(msgdec, err, w.DecoderParams.CallbackArgs, w.DecoderParams.DecoderConfig)
						DecoderErrors.With(
							prometheus.Labels{
								"worker": strconv.Itoa(w.Id),
								"name":   w.Name,
							}).
							Inc()
					}
				} else {
					if w.DecoderParams.DoneCallback != nil {
						timeTrackStart = time.Now()
						success, errcb := w.DecoderParams.DoneCallback(msgdec, w.DecoderParams.CallbackArgs, w.DecoderParams.DecoderConfig)
						timeTrackStop = time.Now()
						DecoderProcessTime.With(
							prometheus.Labels{
								"name": w.Name,
							}).
							Observe(float64((timeTrackStop.Sub(timeTrackStart)).Nanoseconds()) / 1000)

						if success != true {
							log.Errorf("Worker %v: callback problem\n", w.Id)
							DecoderErrors.With(
								prometheus.Labels{
									"worker": strconv.Itoa(w.Id),
									"name":   w.Name,
								}).
								Inc()
						}

						if errcb != nil {
							log.Errorf("Worker %v: callback error %v\n", w.Id, errcb)
							DecoderErrors.With(
								prometheus.Labels{
									"worker": strconv.Itoa(w.Id),
									"name":   w.Name,
								}).
								Inc()
						}
					}
				}
				DecoderStats.With(
					prometheus.Labels{
						"worker": strconv.Itoa(w.Id),
						"name":   w.Name,
					}).
					Inc()
				//w.OutDec<-msgdec
			}
		}
		log.Debugf("Worker %v done", w.Id)
	}()
}

// Stop the worker.
func (w Worker) Stop() {
	log.Debugf("Stopping worker %v", w.Id)
	w.Quit <- true
}

// Processor structure
type Processor struct {
	workerpool    chan chan Message
	workerlist    []Worker
	DecoderParams DecoderParams
	Name          string
}

// Decoder structure. Define the function to call and the config specific to the type of packets.
type DecoderParams struct {
	DecoderFunc   DecoderFunc
	DecoderConfig DecoderConfig
	DoneCallback  DoneCallback
	ErrorCallback ErrorCallback
	CallbackArgs  CallbackArgs
}

func RegisterMetrics() {
	MetricsRegistrationLock.Lock()
	if MetricsRegistered {
		return
	}
	prometheus.MustRegister(DecoderStats)
	prometheus.MustRegister(DecoderErrors)
	prometheus.MustRegister(DecoderTime)
	prometheus.MustRegister(DecoderProcessTime)
	MetricsRegistered = true
	MetricsRegistrationLock.Unlock()
}

// Create a message processor which is going to create all the workers and set-up the pool.
func CreateProcessor(numWorkers int, decoderParams DecoderParams, name string) Processor {
	RegisterMetrics()

	log.Infof("Creating %v message processor with %v workers", name, numWorkers)
	processor := Processor{
		workerpool:    make(chan chan Message),
		workerlist:    make([]Worker, numWorkers),
		DecoderParams: decoderParams,
		Name:          name,
	}
	for i := 0; i < numWorkers; i++ {
		worker := CreateWorker(processor.workerpool, decoderParams, i, name)
		processor.workerlist[i] = worker
	}
	return processor
}

// Start message processor
func (p Processor) Start() {
	log.WithFields(log.Fields{
		"Name": p.Name}).Debug("Starting workers")
	for _, worker := range p.workerlist {
		worker.Start()
	}
}

func (p Processor) Stop() {
	for _, worker := range p.workerlist {
		worker.Stop()
	}
}

// Send a message to be decoded to the pool.
func (p Processor) ProcessMessage(msg Message) {
	sendChannel := <-p.workerpool
	sendChannel <- msg
}
