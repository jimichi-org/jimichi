#!/usr/bin/env bash
# run the correlation sweep inside linux, where the clock is fine grained enough
# to time a round trip through the chain
set -euo pipefail

mkdir -p artifacts
docker build -q --build-arg TARGET=lab -t jimichi/lab:dev . >/dev/null
# a revision names the code only on a committed tree: any change outside the
# reports and the documentation, untracked files included, makes it dirty, so a
# package the image context gains later is covered without a list to keep. A Go
# source that .gitignore hides still goes into the image, so it counts too
rev="$(git rev-parse --short HEAD)"
if [ -n "$(git status --porcelain --untracked-files=normal -- . ':(exclude)artifacts' ':(exclude)docs')" ] ||
	[ -n "$(git ls-files --others --ignored --exclude-standard -- '*.go' go.mod go.sum ':(exclude)artifacts' ':(exclude)docs')" ]; then
	rev="$rev-dirty"
fi
MSYS_NO_PATHCONV=1 docker run --rm   -v "$(pwd)/artifacts:/out"   jimichi/lab:dev -out /out -rev "$rev" "$@"
