IMAGE ?= cloudflare/goflow
VERSION ?= $(shell git describe --tags --always --dirty)
VERSION_DOCKER ?= $(shell git describe --tags --abbrev=0 --always --dirty)

GOOS ?= linux
ARCH ?= $(shell uname -m)

.PHONY: all
all: test-race vet test

.PHONY: clean
clean:
	rm -rf bin

.PHONY: build
build:
	@echo compiling code
	mkdir bin
	GOOS=$(GOOS) go build -ldflags '-X main.version=$(VERSION)' -o bin/goflow-$(GOOS)-$(ARCH) cmd/goflow/goflow.go
	GOOS=$(GOOS) go build -ldflags '-X main.version=$(VERSION)' -o bin/goflow-sflow-$(GOOS)-$(ARCH) cmd/csflow/csflow.go
	GOOS=$(GOOS) go build -ldflags '-X main.version=$(VERSION)' -o bin/goflow-netflow-$(GOOS)-$(ARCH) cmd/cnetflow/cnetflow.go
	GOOS=$(GOOS) go build -ldflags '-X main.version=$(VERSION)' -o bin/goflow-sflow-$(GOOS)-$(ARCH) cmd/cnflegacy/cnflegacy.go


.PHONY: container
container:
	@echo build docker container
	docker build --build-arg VERSION=$(VERSION) -t $(IMAGE):$(VERSION_DOCKER) .

.PHONY: proto
proto:
	@echo generating protobuf
	protoc --go_out=. --plugin=$(PROTOCPATH)protoc-gen-go pb/*.proto

.PHONY: test
test:
	@echo testing code
	go test ./...

.PHONY: vet
vet:
	@echo checking code is vetted
	go vet $(shell go list ./...)

.PHONY: test-race
test-race:
	@echo testing code for races
	go test -race ./...
