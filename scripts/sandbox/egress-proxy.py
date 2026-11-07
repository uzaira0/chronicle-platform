#!/usr/bin/env python3
"""HTTPS egress for the dependency sandbox (scripts/deps-sandbox.sh --network registries).

    egress-proxy.py --allowlist FILE [--port 3128]

The sandbox container sits on an internal Docker network with no gateway; this proxy is the only
other member and also has a route out. It accepts `CONNECT host:443` for the host names listed in
FILE (one per line, `#` comments; a leading `.` admits that domain's subdomains) and refuses every
other request: other ports, IP literals, plain HTTP, unlisted names. It sees only the host name and
forwards the TLS stream unopened. Each decision is one line on stderr (`allow`/`deny host:port`),
which deps-sandbox.sh prints when a sandboxed command fails.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys

HEAD_LIMIT = 16384
TIMEOUT = 30


def load_allowlist(path: str) -> frozenset[str]:
    with open(path, encoding='utf-8') as handle:
        names = {line.split('#', 1)[0].strip().lower() for line in handle}
    return frozenset(name for name in names if name)


def allowed(host: str, allowlist: frozenset[str]) -> bool:
    host = host.lower().rstrip('.')
    try:
        ipaddress.ip_address(host.strip('[]'))
        return False  # names only: an address would bypass the list
    except ValueError:
        pass
    return host in allowlist or any(entry.startswith('.') and host.endswith(entry) for entry in allowlist)


def target(request_line: str) -> tuple[str, int] | None:
    """(host, port) of a well-formed `CONNECT host:port HTTP/1.x` line, else None."""
    parts = request_line.split()
    if len(parts) != 3 or parts[0] != 'CONNECT' or not parts[2].startswith('HTTP/1.'):
        return None
    host, _, port = parts[1].rpartition(':')
    if not host or not port.isdigit():
        return None
    return host, int(port)


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


async def refuse(writer: asyncio.StreamWriter, status: str) -> None:
    writer.write(f'HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'.encode())
    try:
        await writer.drain()
    finally:
        writer.close()


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, allowlist: frozenset[str]) -> None:
    try:
        head = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), TIMEOUT)
    except (TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError):
        writer.close()
        return
    line = head.split(b'\r\n', 1)[0].decode('latin-1')
    request = target(line)
    if request is None:
        print(f'deny {line[:120]!r} (only CONNECT)', file=sys.stderr, flush=True)
        await refuse(writer, '405 Method Not Allowed')
        return
    host, port = request
    if port != 443 or not allowed(host, allowlist):
        print(f'deny {host}:{port}', file=sys.stderr, flush=True)
        await refuse(writer, '403 Forbidden')
        return
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(host, port), TIMEOUT)
    except (TimeoutError, OSError) as error:
        print(f'fail {host}:{port} {error}', file=sys.stderr, flush=True)
        await refuse(writer, '502 Bad Gateway')
        return
    print(f'allow {host}:{port}', file=sys.stderr, flush=True)
    writer.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
    await writer.drain()
    await asyncio.gather(pump(reader, upstream_writer), pump(upstream_reader, writer))


async def serve(allowlist: frozenset[str], port: int) -> None:
    server = await asyncio.start_server(lambda r, w: handle(r, w, allowlist), host='0.0.0.0', port=port,
                                        limit=HEAD_LIMIT)
    print(f'egress-proxy: {len(allowlist)} allowed names, port {port}', file=sys.stderr, flush=True)
    async with server:
        await server.serve_forever()


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--allowlist', required=True)
    parser.add_argument('--port', type=int, default=3128)
    args = parser.parse_args(argv)
    asyncio.run(serve(load_allowlist(args.allowlist), args.port))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
