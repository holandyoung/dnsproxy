#!/bin/sh
set -eu

script_dir=$(dirname -- "$0")
CDPATH='' cd -- "$script_dir/.."

unformatted=$(git ls-files -z --cached --others --exclude-standard '*.go' | xargs -0 gofmt -l)
if [ -n "$unformatted" ]; then
    printf 'Go files need formatting:\n%s\n' "$unformatted" >&2
    exit 1
fi
go mod verify
for platform in darwin freebsd linux openbsd windows; do
    GOOS="$platform" go vet ./...
done
go tool staticcheck --matrix ./... <<'EOF'
darwin:  GOOS=darwin
freebsd: GOOS=freebsd
linux:   GOOS=linux
openbsd: GOOS=openbsd
windows: GOOS=windows
EOF
go tool nilness ./...
go tool ineffassign ./...
go tool unparam ./...
go tool fieldalignment ./...
go tool shadow --strict ./...
go tool errcheck ./...
go tool gosec --exclude-generated --fmt=golint --quiet ./...
shellcheck -o all -e SC2250 scripts/check.sh scripts/hooks/* scripts/make/*.sh
git ls-files -z --cached --others --exclude-standard '*.json' | xargs -0 jq empty
go tool yamlfmt --lint .github/workflows/*.yaml
go test -race -shuffle=on -count=2 -timeout=3m ./...
go tool govulncheck ./...
