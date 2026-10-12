.PHONY: all gen build test lint clean image

all: lint test build

gen:
	buf generate
	buf generate --template buf.gen.schema.yaml --type urljail.report.v0.Report
	mv api/schema/tmp/urljail.report.v0.Report.schema.bundle.json api/schema/report.v0.schema.json
	rm -rf api/schema/tmp

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
