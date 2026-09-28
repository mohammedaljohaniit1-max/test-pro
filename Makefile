# Cross-compile helpers for non-Windows hosts. On Windows use build.bat.
VERSION ?= 4.0.0
MODULE  := github.com/mohammedaljohaniit1-max/test-pro
LDFLAGS := -s -w -X $(MODULE)/internal/server.Version=$(VERSION)

.PHONY: all test vet windows windows-arm64 demo clean

all: vet test windows

vet:
	go vet ./...
	GOOS=windows go vet ./...

test:
	go test -race -count=1 ./...

windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/syspulse.exe ./cmd/syspulse

windows-arm64:
	CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/syspulse-arm64.exe ./cmd/syspulse

# Synthetic-data dashboard that runs on any OS (UI development / review).
demo:
	go run ./cmd/syspulse-demo

clean:
	rm -rf dist bin
