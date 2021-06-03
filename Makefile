wasm: go.mod go.sum *.go
	docker run --rm -v ${PWD}:/src -w /src ghcr.io/kubewarden/tinygo/tinygo-dev:w14-2021 tinygo build -o policy.wasm -target=wasi -no-debug .

annotate:
	kwctl annotate -m metadata.yml -o annotated.wasm policy.wasm

test:
	go test -v

e2e-tests:
	bats e2e.bats

.PHONY: clean
clean:
	go clean
	rm -f policy.wasm
