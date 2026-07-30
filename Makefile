.PHONY: build docker-build fmt-check hadolint test vet vulncheck

VERSION ?= dev
LDFLAGS ?= -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o build/zabbix-discord-ops ./cmd/zabbix-discord-ops
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o build/register-commands ./cmd/register-commands

docker-build:
	docker build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg GIT_SHA="$$(git rev-parse HEAD)" \
		--build-arg CREATED="$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
		-t zabbix-discord-ops:"$(VERSION)" .

fmt-check:
	test -z "$$(gofmt -l cmd internal)"

hadolint:
	docker run --rm -i hadolint/hadolint:v2.14.0@sha256:27086352fd5e1907ea2b934eb1023f217c5ae087992eb59fde121dce9c9ff21e < Dockerfile

test:
	go test -race ./...

vet:
	go vet ./...

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
