SOURCE_FILES := $(shell find . -type f -name '*.go')
CONTAINER_IMAGE ?= tinygo/tinygo:0.37.0

policy.wasm: $(SOURCE_FILES) go.mod go.sum
	docker run \
		--rm \
		-e GOFLAGS="-buildvcs=false" \
		-v ${PWD}:/src \
		-w /src \
		$(CONTAINER_IMAGE) \
		tinygo build -o policy.wasm -target=wasip1 -no-debug .


annotated-policy.wasm: policy.wasm metadata.yml
	kwctl annotate -m metadata.yml -u README.md -o annotated-policy.wasm policy.wasm

.PHONY: test
test:
	go test -v ./...

.PHONY: e2e-tests
e2e-tests: annotated-policy.wasm
	bats e2e.bats

.PHONY: lint
lint:
	go vet ./...
	golangci-lint run

.PHONY: clean
clean:
	go clean
	rm -f policy.wasm annotated-policy.wasm
