# https://github.com/rnubel/pgmgr/issues/47
GO111MODULE := on
export GO111MODULE

GO := "/usr/lib/go-1.11/bin/go"

setup:
	$(GO) version

install: setup
	$(GO) install

build: setup
	$(GO) build -ldflags '-s -w' -o planb ./main.go

test: setup
	$(GO) test
