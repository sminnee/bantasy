.PHONY: default lint test race yaegi_test

export GO111MODULE=on

default: lint test yaegi_test

lint:
	golangci-lint run

test:
	go test -v -cover ./...

# Needs cgo (a C compiler).
race:
	CGO_ENABLED=1 go test -race ./...

# Runs the suite in the interpreter Traefik uses for plugins.
yaegi_test:
	yaegi test -v .
