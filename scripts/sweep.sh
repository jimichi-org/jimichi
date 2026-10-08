#!/usr/bin/env bash
# run the correlation sweep inside linux, where the clock is fine grained enough
# to time a round trip through the chain
set -euo pipefail

mkdir -p artifacts
docker build -q --build-arg TARGET=lab -t jimichi/lab:dev . >/dev/null
# a revision names the code only on a committed tree: any change outside the
# reports and the documentation, untracked files included, makes it dirty, so a
# package the image context gains later is covered without a list to keep. A Go
# source that .gitignore hides still goes into the image, so it counts too, but
# only inside the directories .dockerignore lets in: an ignored .dev holding Go
# stays out of the image. git's * crosses /, so relay/*.go covers relay/core too
image_dirs="$(sed -n 's/^!\([a-z0-9]*\)$/\1/p' .dockerignore)"
image_sources=(go.mod go.sum)
for dir in $image_dirs; do
	image_sources+=("$dir/*.go")
done
rev="$(git rev-parse --short HEAD)"
if [ -n "$(git status --porcelain --untracked-files=normal -- . ':(exclude)artifacts' ':(exclude)docs')" ] ||
	[ -n "$(git ls-files --others --ignored --exclude-standard -- "${image_sources[@]}")" ]; then
	rev="$rev-dirty"
fi
MSYS_NO_PATHCONV=1 docker run --rm   -v "$(pwd)/artifacts:/out"   jimichi/lab:dev -out /out -rev "$rev" "$@"
