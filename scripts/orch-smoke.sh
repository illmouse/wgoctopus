#!/bin/sh
set -eu
name=wgoctopus-orch-smoke-$$
key=$(python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
token=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker run -d --name "$name" -p 127.0.0.1:18089:8080 -e WGOCTOPUS_MASTER_KEY="$key" -e WGOCTOPUS_API_TOKEN="$token" wgoctopus-orchestrator:dev >/dev/null
i=0
until python3 -c 'import urllib.request; urllib.request.urlopen("http://127.0.0.1:18089/readyz",timeout=1)' 2>/dev/null; do
  i=$((i+1)); [ "$i" -lt 60 ] || { docker logs "$name"; exit 1; }; sleep 1
done
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:18089/v1/status)
[ "$code" = 401 ]
code=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $token" http://127.0.0.1:18089/v1/status)
[ "$code" = 200 ]
