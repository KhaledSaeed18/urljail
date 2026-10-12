.PHONY: all gen build test lint clean

all: lint test build

gen:
	buf generate

build:
	go build -o bin/ ./cmd/...

test:
	go test ./...

lint:
	buf lint
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"

clean:
	rm -rf bin/
