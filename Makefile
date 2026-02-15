.PHONY: all build test clean init demo

BINARY_DIR := bin
ZTCA := $(BINARY_DIR)/ztca
RA := $(BINARY_DIR)/ra
CRL_PUBLISHER := $(BINARY_DIR)/crl-publisher
AGENT := $(BINARY_DIR)/agent

all: build

build: $(ZTCA) $(RA) $(CRL_PUBLISHER) $(AGENT)
	@if command -v mvn >/dev/null 2>&1; then $(MAKE) -C services/service-b build; else echo "Skipping service-b (mvn not found)"; fi
	@echo "Note: service-a (C++) requires OpenSSL; service-b requires Maven. Use: docker compose build"

$(ZTCA):
	@mkdir -p $(BINARY_DIR)
	go build -o $(ZTCA) ./cmd/ztca

$(RA):
	@mkdir -p $(BINARY_DIR)
	go build -o $(RA) ./cmd/ra

$(CRL_PUBLISHER):
	@mkdir -p $(BINARY_DIR)
	go build -o $(CRL_PUBLISHER) ./cmd/crl-publisher

$(AGENT):
	@mkdir -p $(BINARY_DIR)
	go build -o $(AGENT) ./cmd/agent

test:
	go test ./...
	$(MAKE) -C services/service-a test
	$(MAKE) -C services/service-b test

clean:
	rm -rf $(BINARY_DIR) ca/
	$(MAKE) -C services/service-a clean
	$(MAKE) -C services/service-b clean

init: $(ZTCA)
	./$(ZTCA) init

demo: build init
	./demo.sh mvp

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down
