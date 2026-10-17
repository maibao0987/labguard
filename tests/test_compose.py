"""Guard against invalid mount paths introduced by YAML flow-list parsing."""

import runpy
from pathlib import Path

from labguard.relay import forward


def test_compose_security_contract():
    runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/check_compose.py"))


def test_relay_forwards_to_fixed_destination_and_preserves_response(monkeypatch):
    import asyncio

    import labguard.relay as relay

    async def exercise():
        async def echo(reader, writer):
            request = await reader.readuntil(b"\r\n\r\n")
            assert request.startswith(b"GET /health HTTP/1.1")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            await writer.drain()
            writer.close()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        real_open = asyncio.open_connection
        calls = []

        async def connect(host, requested_port):
            calls.append((host, requested_port))
            return await real_open("127.0.0.1", port)

        monkeypatch.setattr(relay.asyncio, "open_connection", connect)
        ingress = await asyncio.start_server(lambda r, w: forward(r, w, "manager"), "127.0.0.1", 0)
        try:
            reader, writer = await real_open("127.0.0.1", ingress.sockets[0].getsockname()[1])
            # Host input is opaque bytes and cannot change the fixed upstream.
            writer.write(b"GET /health HTTP/1.1\r\nHost: attacker.example\r\n\r\n")
            await writer.drain()
            assert (await asyncio.wait_for(reader.read(), timeout=3)).endswith(b"\r\n\r\nok")
            assert calls == [("manager", 5000)]
            writer.close()
            await writer.wait_closed()
        finally:
            ingress.close()
            upstream.close()
            await ingress.wait_closed()
            await upstream.wait_closed()

    asyncio.run(exercise())
