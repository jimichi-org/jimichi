#!/usr/bin/env bash
# rebuild the images, push them into kind and verify the chain still works
set -euo pipefail

CLUSTER="${CLUSTER:-jimichi}"
NAMESPACE="${NAMESPACE:-jimichi}"

go vet ./...
go test ./...

docker build -q --build-arg TARGET=relay -t jimichi/relay:dev . >/dev/null
docker build -q --build-arg TARGET=client -t jimichi/client:dev . >/dev/null
bash scripts/e2e.sh
