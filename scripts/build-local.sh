#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
platform="${1:-linux/amd64}"
case "$platform" in linux/amd64|linux/arm64) ;; *) echo 'Use linux/amd64 or linux/arm64' >&2; exit 2 ;; esac
version=$(tr -d '\n' < VERSION)
arch=${platform#linux/}
tag="unifi-insights-plus:${version}-${arch}"
mkdir -p .local/buildx
export BUILDX_CONFIG="${BUILDX_CONFIG:-$(pwd)/.local/buildx}"
docker buildx build --platform "$platform" --load --tag "$tag" .
docker tag "$tag" "unifi-insights-plus:$version"
mkdir -p .local/artifacts
archive=".local/artifacts/unifi-insights-plus-${version}-${arch}.tar.gz"
# Stage output so an interrupted export cannot appear complete.
docker image save "$tag" "unifi-insights-plus:$version" > "$archive.tmp.tar"
gzip -c "$archive.tmp.tar" > "$archive.tmp"
mv "$archive.tmp" "$archive"
rm "$archive.tmp.tar"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$archive" > "$archive.sha256"
else
  shasum -a 256 "$archive" > "$archive.sha256"
fi
printf 'Local image: %s\nArchive: %s\n' "$tag" "$archive"
