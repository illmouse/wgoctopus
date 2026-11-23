import asyncio
import hashlib
import json
import urllib.parse


class FakeAgent:
    def __init__(self, token="test-token-not-secret", delay=0, metrics_text="# TYPE fake counter\nfake 1\n", metrics_status=200, metrics_delay=0):
        self.token, self.delay = token, delay
        self.metrics_text, self.metrics_status, self.metrics_delay = metrics_text, metrics_status, metrics_delay
        self.requests, self.state = [], {"revision": 0, "interfaces": []}
        self._server = None
        self.port = 0

    async def start(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader, writer):
        try:
            line = await reader.readline()
            method, target, _ = line.decode().split()
            headers = {}
            while line := await reader.readline():
                if line == b"\r\n":
                    break
                key, value = line.decode().split(":", 1)
                headers[key.lower()] = value.strip()
            length = int(headers.get("content-length", 0))
            body = json.loads(await reader.readexactly(length)) if length else None
            parsed = urllib.parse.urlsplit(target)
            self.requests.append((method, parsed.path, parsed.query, body))
            if self.delay:
                await asyncio.sleep(self.delay)
            status, payload, content_type = 200, b"", "text/plain"
            if parsed.path == "/metrics":
                if self.metrics_delay:
                    await asyncio.sleep(self.metrics_delay)
                status = self.metrics_status
                payload = self.metrics_text.encode()
            elif parsed.path == "/healthz":
                payload = b"ok"
            elif headers.get("authorization") != f"Bearer {self.token}":
                status, payload, content_type = 401, b'{"error":"unauthorized"}', "application/json"
            elif parsed.path == "/v1/state" and method == "GET":
                clean = json.loads(json.dumps(self.state))
                for interface in clean.get("interfaces", []):
                    interface.pop("private_key", None)
                    for peer in interface.get("peers", []):
                        peer.pop("preshared_key", None)
                checksum_state = json.loads(json.dumps(self.state))
                checksum_state.pop("revision", None)
                data = {"revision": self.state["revision"], "checksum": hashlib.sha256(json.dumps(checksum_state, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "state": clean}
                payload, content_type = json.dumps(data).encode(), "application/json"
            elif parsed.path == "/v1/state" and method == "PUT":
                if not isinstance(body, dict) or type(body.get("revision")) is not int:
                    status, payload = 422, b'{"error":"invalid state"}'
                    content_type = "application/json"
                elif body["revision"] <= self.state["revision"]:
                    status, payload = 409, b'{"error":"stale revision","reasons":[]}'
                    content_type = "application/json"
                else:
                    reasons = []
                    old = {item.get("name"): item for item in self.state.get("interfaces", [])}
                    for item in body.get("interfaces", []):
                        prior = old.get(item.get("name"))
                        if prior:
                            for field in ("private_key", "listen_port", "obfuscation"):
                                if item.get(field) != prior.get(field):
                                    reasons.append(f"{item.get('name')}: {field} changed")
                    allow = urllib.parse.parse_qs(parsed.query).get("allow_dangerous") == ["true"]
                    if reasons and not allow:
                        status, payload, content_type = 409, json.dumps({"error":"dangerous change", "reasons":reasons}).encode(), "application/json"
                    else:
                        self.state = body
                        status = 204
            else:
                status, payload = 404, b"not found"
            phrase = {200:"OK",204:"No Content",401:"Unauthorized",404:"Not Found",409:"Conflict",422:"Unprocessable Entity"}.get(status,"Error")
            writer.write(f"HTTP/1.1 {status} {phrase}\r\nContent-Length: {len(payload)}\r\nContent-Type: {content_type}\r\nConnection: close\r\n\r\n".encode() + payload)
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ValueError):
            pass
        finally:
            writer.close()
            await writer.wait_closed()
