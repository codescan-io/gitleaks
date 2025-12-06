.PHONY: test test-cover failfast profile clean format build

PKG=github.com/zricethezav/gitleaks
VERSION := `git fetch --tags && git tag | sort -V | tail -1`
LDFLAGS=-ldflags "-X=github.com/zricethezav/gitleaks/v8/version.Version=$(VERSION)"
COVER=--cover --coverprofile=cover.out
BINARY_NAME=gitleaks-server

test-cover:
	go test -v ./... --race $(COVER) $(PKG)
	go tool cover -html=cover.out

format:
	go fmt ./...

test: config/gitleaks.toml format
	go test -v ./... --race $(PKG)

failfast: format
	go test -failfast ./...

build: config/gitleaks.toml format
	go mod tidy
	go build $(LDFLAGS)
ifeq ($(GOOS),windows)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BINARY_NAME)_$(GOOS)_$(GOARCH).exe .
else
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(BINARY_NAME)_$(GOOS)_$(GOARCH) .
endif
	
lint:
	golangci-lint run

clean:
	rm -rf profile
	rm -f $(BINARY_NAME)-*
	find . -type f -name '*.got.*' -delete
	find . -type f -name '*.out' -delete

profile: build
	./scripts/profile.sh './gitleaks' '.'

config/gitleaks.toml: $(wildcard cmd/generate/config/**/*)
	go generate ./...

all: darwin_amd64 darwin_arm64 linux_amd64 linux_arm64 windows_amd64 windows_arm64

darwin_amd64:
	$(MAKE) GOOS=darwin GOARCH=amd64 build

darwin_arm64:
	$(MAKE) GOOS=darwin GOARCH=arm64 build

linux_amd64:
	$(MAKE) GOOS=linux GOARCH=amd64 build

linux_arm64:
	$(MAKE) GOOS=linux GOARCH=arm64 build

windows_amd64:
	$(MAKE) GOOS=windows GOARCH=amd64 build

windows_arm64:
	$(MAKE) GOOS=windows GOARCH=arm64 build

