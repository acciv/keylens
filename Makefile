.PHONY: all build test clean test-python test-go test-rust test-cpp

all: build

build:
	cd go && go build ./...
	cd rust && cargo build --release --offline
	$(MAKE) -C cpp

test: test-python test-go test-rust test-cpp

test-python:
	python3 -m unittest discover -s tests -v

test-go:
	cd go && go test ./...

test-rust:
	cd rust && cargo test --offline

test-cpp:
	$(MAKE) -C cpp test

clean:
	cd rust && cargo clean
	$(MAKE) -C cpp clean
