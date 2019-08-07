EXTENSION ?= 
DIST_DIR ?= dist/
GOOS ?= linux
ARCH ?= $(shell uname -m)
BUILDINFOSDET ?= 

DOCKER_REPO   := cloudflare/
GOFLOW_NAME    := goflow
GOFLOW_VERSION := $(shell git describe --tags $(git rev-list --tags --max-count=1))
VERSION_PKG   := $(shell echo $(GOFLOW_VERSION) | sed 's/^v//g')
ARCH          := x86_64
LICENSE       := BSD-3
URL           := https://github.com/cloudflare/goflow
DESCRIPTION   := GoFlow: an sFlow/IPFIX/NetFlow v9/v5 collector to Kafka
BUILDINFOS    :=  ($(shell date +%FT%T%z)$(BUILDINFOSDET))
LDFLAGS       := '-X main.version=$(GOFLOW_VERSION) -X main.buildinfos=$(BUILDINFOS)'

OUTPUT_GOFLOW := $(DIST_DIR)goflow-$(GOFLOW_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

OUTPUT_GOFLOW_LIGHT_SFLOW := $(DIST_DIR)goflow-sflow-$(GOFLOW_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)
OUTPUT_GOFLOW_LIGHT_NF    := $(DIST_DIR)goflow-netflow-$(GOFLOW_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)
OUTPUT_GOFLOW_LIGHT_NFV5  := $(DIST_DIR)goflow-nflegacy-$(GOFLOW_VERSION)-$(GOOS)-$(ARCH)$(EXTENSION)

.PHONY: all
all: test-race vet test

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

.PHONY: prepare
prepare:
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean:
	rm -rf $(DIST_DIR)

.PHONY: build-goflow
build-goflow: prepare
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW) cmd/goflow/goflow.go

.PHONY: build-goflow-light
build-goflow-light: prepare
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW_LIGHT_SFLOW) cmd/csflow/csflow.go
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW_LIGHT_NF) cmd/cnetflow/cnetflow.go
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW_LIGHT_NFV5) cmd/cnflegacy/cnflegacy.go

.PHONY: docker-goflow
docker-goflow:
	docker build -t $(DOCKER_REPO)$(GOFLOW_NAME):$(GOFLOW_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile .

.PHONY: package-deb-goflow
package-deb-goflow: prepare
	fpm -s dir -t deb -n $(GOFLOW_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)"  \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE)" \
       	--deb-no-default-config-files \
        --package $(DIST_DIR) \
        $(OUTPUT_GOFLOW)=/usr/bin/goflow \
        package/goflow.service=/lib/systemd/system/goflow.service \
        package/goflow.env=/etc/default/goflow

.PHONY: package-rpm-goflow
package-rpm-goflow: prepare
	fpm -s dir -t rpm -n $(GOFLOW_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)" \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE) "\
        --package $(DIST_DIR) \
        $(OUTPUT_GOFLOW)=/usr/bin/goflow \
        package/goflow.service=/lib/systemd/system/goflow.service \
        package/goflow.env=/etc/default/goflow
