"""Localhost ingress with three immutable TCP destinations; no dynamic target API."""

import asyncio

TARGETS = {5000: "manager", 5001: "vulnerable-web", 5002: "fixed-web"}


async def pipe(reader, writer):
    try:
        while data := await asyncio.wait_for(reader.read(16384), timeout=30):
            writer.write(data)
            await asyncio.wait_for(writer.drain(), timeout=10)
    finally:
        writer.close()


async def forward(reader, writer, target):
    upstream_writer = None
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(target, 5000), timeout=3
        )
        tasks = [
            asyncio.create_task(pipe(reader, upstream_writer)),
            asyncio.create_task(pipe(upstream_reader, writer)),
        ]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)
    except (OSError, TimeoutError):
        pass
    finally:
        writer.close()
        if upstream_writer:
            upstream_writer.close()


async def main():
    servers = []
    for port, target in TARGETS.items():

        async def handle(reader, writer, destination=target):
            await forward(reader, writer, destination)

        servers.append(await asyncio.start_server(handle, "0.0.0.0", port, limit=65536, backlog=32))
    await asyncio.gather(*(server.serve_forever() for server in servers))


if __name__ == "__main__":
    asyncio.run(main())
