#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'Usage: %s <image:tag> <ssh-target>\n' "$0" >&2
  exit 2
fi

docker save "$1" | gzip | ssh "$2" 'gunzip | docker load'
