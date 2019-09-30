package decoder

import (
	"time"
)

type Message interface{}
type MessageDecoded interface{}

type DecoderFunc func(Message interface{}) error
type DoneCallback func(string, int, time.Time, time.Time)
type ErrorCallback func(string, int, time.Time, time.Time, error)

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
		//log.Debugf("Worker %v started", w.Id)
		for {
			select {
			case <-w.Quit:
				break
			case w.WorkerPool <- w.InMsg:
				msg := <-w.InMsg
				timeTrackStart := time.Now()
				err := w.DecoderParams.DecoderFunc(msg)
				timeTrackStop := time.Now()

				if err != nil && w.DecoderParams.ErrorCallback != nil {
					w.DecoderParams.ErrorCallback(w.Name, w.Id, timeTrackStart, timeTrackStop, err)
				} else if err == nil && w.DecoderParams.DoneCallback != nil {
					w.DecoderParams.DoneCallback(w.Name, w.Id, timeTrackStart, timeTrackStop)
				}
			}
		}
		//log.Debugf("Worker %v done", w.Id)
	}()
}

// Stop the worker.
func (w Worker) Stop() {
	//log.Debugf("Stopping worker %v", w.Id)
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
	DoneCallback  DoneCallback
	ErrorCallback ErrorCallback
}

// Create a message processor which is going to create all the workers and set-up the pool.
func CreateProcessor(numWorkers int, decoderParams DecoderParams, name string) Processor {
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
