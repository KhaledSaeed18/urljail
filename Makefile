.PHONY: all gen build test lint clean image

all: lint test build

gen:
	buf generate

build:
	go build -o bin/ ./cmd/urljail ./cmd/urljaild

image:
	images/debian-chrome/build.sh

test:
	go test ./...

lint:
	buf lint
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"

clean:
	rm -rf bin/
