#!/bin/sh
set -eu

unformatted=$(git ls-files -z '*.go' | xargs -0 gofmt -l)
if [ -n "$unformatted" ]; then
    printf 'Go files need formatting:\n%s\n' "$unformatted" >&2
    exit 1
fi
go mod verify
go vet ./...
go test -race -shuffle=on -count=2 -timeout=3m ./...
go tool govulncheck ./...
