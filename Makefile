GO ?= go
GOFMT ?= gofmt "-s"
GO_VERSION=$(shell $(GO) version | cut -c 14- | cut -d' ' -f1 | cut -d'.' -f2)
PACKAGES ?= $(shell $(GO) list ./...)
VETPACKAGES ?= $(shell $(GO) list ./... | grep -v /examples/)
GOFILES := $(shell find . -name "*.go")
TESTFOLDER := $(shell $(GO) list ./... | grep -E 'utils$$')
DOCKER ?= docker
TEST_FILES := $(shell find . -name '*_test.go')

.PHONY: test
test:
	@echo "Starting test process..."
	@mkdir -p coverage # Ensure the coverage directory exists
	@packages=$$(go list ./...); \
	for pkg in $${packages}; do \
	    echo "Running tests in $${pkg}"; \
	    $(GO) test -v $(TESTTAGS) -covermode=count -coverprofile="coverage/$${pkg##*/}.out" "$${pkg}"; \
	done
	@echo "Combining coverage profiles..."
	gocovmerge coverage/*.out > coverage/merged.out
	@echo "Finished test process."

.PHONY: fmt
fmt:
	$(GOFMT) -w $(GOFILES)

.PHONY: fmt-check
fmt-check:
	@diff=$$($(GOFMT) -d $(GOFILES)); \
	if [ -n "$$diff" ]; then \
		echo "Please run 'make fmt' and commit the result:"; \
		echo "$${diff}"; \
		exit 1; \
	fi;

.PHONY: lint
lint:
	$(shell golangci-lint run ./...)

.PHONY: clean
clean:
	@find . -name 'profile.out' -exec rm -f {} +
	$(shell rm -rf bin)
	$(shell rm -rf shiftsbom-validator)
	$(shell rm -rf coverage)

.PHONY: build
build:
	$(GO) build -o bin/ShiftSBOM-Validate

.PHONY: markdown-lint
markdown-lint:
	$(DOCKER) run --rm -it \
		-v "$(shell pwd)":/build \
		--workdir /build \
		markdownlint/markdownlint:0.13.0 *.md
