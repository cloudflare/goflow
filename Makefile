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
all: test-race vet test ## Run all tests and checks.

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet


.PHONY: proto
proto:
	@echo generating protobuf
	protoc --go_out=. --plugin=$(PROTOCPATH)protoc-gen-go pb/*.proto

.PHONY: test
test: ## Run unit tests.
	@echo testing code
	go test ./...

.PHONY: vet
vet: ## Run go vet to check for potential issues.
	@echo checking code is vetted
	go vet $(shell go list ./...)

.PHONY: test-race
test-race: ## Run tests with race condition detection.
	@echo testing code for races
	go test -race ./...

.PHONY: prepare
prepare: ## Prepare necessary directories for build output.
	mkdir -p $(DIST_DIR)

.PHONY: clean
clean: ## Clean build artifacts.
	rm -rf $(DIST_DIR)

.PHONY: build-goflow
build-goflow: prepare ## Build the goflow binary.
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW) cmd/goflow/goflow.go

.PHONY: docker-goflow
docker-goflow: ## Build the Docker image for goflow.
	docker build -t $(DOCKER_REPO)$(GOFLOW_NAME):$(GOFLOW_VERSION) --build-arg LDFLAGS=$(LDFLAGS) -f Dockerfile .

.PHONY: build-goflow-light
build-goflow-light: prepare ## Build the lightweight goflow binaries.
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW_LIGHT_SFLOW) cmd/csflow/csflow.go
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW_LIGHT_NF) cmd/cnetflow/cnetflow.go
	go build -ldflags $(LDFLAGS) -o $(OUTPUT_GOFLOW_LIGHT_NFV5) cmd/cnflegacy/cnflegacy.go

.PHONY: package-deb-goflow
package-deb-goflow: prepare ## Package goflow as a Debian package.
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
package-rpm-goflow: prepare ## Package goflow as an RPM package.
	fpm -s dir -t rpm -n $(GOFLOW_NAME) -v $(VERSION_PKG) \
        --description "$(DESCRIPTION)" \
        --url "$(URL)" \
        --architecture $(ARCH) \
        --license "$(LICENSE) "\
        --package $(DIST_DIR) \
        $(OUTPUT_GOFLOW)=/usr/bin/goflow \
        package/goflow.service=/lib/systemd/system/goflow.service \
        package/goflow.env=/etc/default/goflow
