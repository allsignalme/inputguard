GO_ENV ?= GOMAXPROCS=2 GOMEMLIMIT=1500MiB
FUZZTIME ?= 30s

.PHONY: test lint fuzz bench cover check golden js-test js-check

test:
	$(GO_ENV) go test -count=1 ./...

lint:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)
	go vet ./...

# Each fuzz target in turn (go test fuzzes one target at a time).
fuzz:
	go test -run '^$$' -fuzz '^FuzzProcessJSON$$' -fuzztime $(FUZZTIME) .
	go test -run '^$$' -fuzz '^FuzzProcessString$$' -fuzztime $(FUZZTIME) .
	go test -run '^$$' -fuzz '^FuzzParity_CleanString$$' -fuzztime $(FUZZTIME) .

bench:
	go test -run '^$$' -bench . -benchmem .

cover:
	go test -count=1 -coverpkg=./,./httpguard,./internal/norm -coverprofile=cover.out ./...
	go tool cover -func=cover.out | tail -1

check: lint test

# The JavaScript port: regenerate the golden output and the tables it reads, then check it.
golden:
	go test -count=1 -run 'TestGolden|TestJSTables' -update .

js-test:
	cd js && npm test

js-check:
	cd js && npm ci && npm run check
