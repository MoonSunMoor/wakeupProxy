VERSION ?= 0.1.0
ARCH ?= arm64
OUT_DIR ?= dist

.PHONY: all build build-arm64 test deb clean

all: test deb

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(OUT_DIR)/wolproxy ./cmd/wolproxy

build-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(OUT_DIR)/wolproxy-linux-arm64 ./cmd/wolproxy

test:
	go test -race ./...

deb:
	go run ./cmd/build-deb -version "$(VERSION)" -arch "$(ARCH)" -out "$(OUT_DIR)"

clean:
	rm -rf $(OUT_DIR)
