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

docker-build: build
	git diff-index --quiet HEAD -- || exit 1
	docker build . -t 629980096842.dkr.ecr.us-east-1.amazonaws.com/tsuru-planb:`git rev-parse --verify HEAD`

docker-push: docker-build
	docker push 629980096842.dkr.ecr.us-east-1.amazonaws.com/tsuru-planb:`git rev-parse --verify HEAD`
