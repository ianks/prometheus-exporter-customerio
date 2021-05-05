#!/bin/bash

set -euo pipefail

version="$1"
git_tag="v$version"
docker_tag="ianks/prometheus-exporter-customerio:$git_tag"

docker build . --tag "$docker_tag"
docker push "$docker_tag"

rm -rf build
mkdir -p build
helm package ./charts/prometheus-exporter-customerio -d build

gh release create "$git_tag" "build/prometheus-exporter-customerio-$version.tgz#Helm Chart"