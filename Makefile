.PHONY: all gen build test lint clean image selinux fuzz

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

# Needs selinux-policy-devel. The built module is committed, like the eBPF object.
selinux:
	cd selinux && $(MAKE) -f /usr/share/selinux/devel/Makefile urljail.pp && rm -rf tmp

test:
	go test ./...

lint:
	buf lint
	go vet ./...
	test -z "$$(gofmt -l cmd internal)"

clean:
	rm -rf bin/

# Parsers the root daemon runs on guest-controlled data (threat model review). FUZZTIME=5m for longer.
FUZZTIME ?= 30s
fuzz:
	go test ./internal/capture/ -run '^$$' -fuzz '^FuzzParseClientHello$$' -fuzztime $(FUZZTIME)
	go test ./internal/capture/ -run '^$$' -fuzz '^FuzzParseHTTPHost$$' -fuzztime $(FUZZTIME)
	go test ./internal/capture/ -run '^$$' -fuzz '^FuzzReassemble$$' -fuzztime $(FUZZTIME)
	go test ./internal/report/ -run '^$$' -fuzz '^FuzzBuild$$' -fuzztime $(FUZZTIME)
	go test ./internal/report/ -run '^$$' -fuzz '^FuzzBuildHost$$' -fuzztime $(FUZZTIME)
	go test ./internal/netns/ -run '^$$' -fuzz '^FuzzParseReply$$' -fuzztime $(FUZZTIME)
	go test ./internal/netns/ -run '^$$' -fuzz '^FuzzParseBlocked$$' -fuzztime $(FUZZTIME)
	go test ./internal/netns/ -run '^$$' -fuzz '^FuzzParseCounters$$' -fuzztime $(FUZZTIME)
	go test ./internal/feeds/ -run '^$$' -fuzz '^FuzzNormalize$$' -fuzztime $(FUZZTIME)
	go test ./internal/ctlog/ -run '^$$' -fuzz '^FuzzParseDataTile$$' -fuzztime $(FUZZTIME)
