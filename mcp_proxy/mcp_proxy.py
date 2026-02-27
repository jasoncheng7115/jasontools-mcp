#!/usr/bin/env python3
"""
MCP HTTP Proxy + SSE Bridge

A simple HTTP/HTTPS proxy that allows MCP servers to connect to
remote hosts through a single local port, with optional SSE bridge
to expose stdio MCP servers over HTTP SSE transport.

Usage:
    python mcp_proxy.py                              # Proxy only
    python mcp_proxy.py --port 28080 --sse cmd arg1  # Proxy + SSE bridge

Then set in Claude Desktop config for each MCP server:
    "env": {
        "HTTP_PROXY": "http://127.0.0.1:28080",
        "HTTPS_PROXY": "http://127.0.0.1:28080",
        ...
    }

Author: Jason Cheng (jason@jason.tools)
License: MIT
"""

import asyncio
import sys
import re
import json
import uuid
import functools
import argparse

DEFAULT_PORT = 28080
KEEPALIVE_INTERVAL = 15  # seconds


class Session:
    """Represents an active SSE client session bridging to a stdio MCP server."""

    __slots__ = ('session_id', 'process', 'response_writer', 'active', 'lock')

    def __init__(self, session_id, process, response_writer):
        self.session_id = session_id
        self.process = process
        self.response_writer = response_writer
        self.active = True
        self.lock = asyncio.Lock()


# Module-level session store
sessions: dict[str, Session] = {}


def parse_args():
    parser = argparse.ArgumentParser(
        description='MCP HTTP Proxy + SSE Bridge',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python mcp_proxy.py                              # Proxy only (port 28080)
  python mcp_proxy.py -p 9000                      # Proxy on port 9000
  python mcp_proxy.py --sse npx -y @modelcontextprotocol/server-everything
  python mcp_proxy.py --sse python my_mcp_server.py
""")
    parser.add_argument('--port', '-p', type=int, default=DEFAULT_PORT,
                        help=f'Port to listen on (default: {DEFAULT_PORT})')
    parser.add_argument('--sse', nargs=argparse.REMAINDER, default=None,
                        metavar='CMD',
                        help='Stdio MCP server command to bridge via SSE')
    return parser.parse_args()


async def pipe(reader, writer):
    """Copy data bidirectionally"""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except:
            pass


async def cleanup_session(session_id):
    """Clean up a session: close stdin, terminate process, remove from store."""
    session = sessions.get(session_id)
    if session is None:
        return

    session.active = False

    # Close stdin to signal the child
    try:
        session.process.stdin.close()
    except:
        pass

    # Terminate, wait with timeout, then kill if needed
    try:
        session.process.terminate()
    except:
        pass
    try:
        await asyncio.wait_for(session.process.wait(), timeout=5)
    except asyncio.TimeoutError:
        try:
            session.process.kill()
        except:
            pass

    # Close the SSE client connection
    try:
        session.response_writer.close()
        await session.response_writer.wait_closed()
    except:
        pass

    sessions.pop(session_id, None)
    print(f"[SSE] Session {session_id[:8]}… cleaned up", flush=True)


async def sse_write(writer, data, lock):
    """Write data to SSE client, protected by lock."""
    async with lock:
        try:
            writer.write(data)
            await writer.drain()
        except:
            raise


async def bridge_stdout_to_sse(session):
    """Read lines from child stdout and forward as SSE message events."""
    try:
        while session.active:
            line = await session.process.stdout.readline()
            if not line:
                break
            text = line.decode('utf-8', errors='replace').rstrip('\n').rstrip('\r')
            if not text:
                continue
            sse_data = f"event: message\ndata: {text}\n\n".encode()
            await sse_write(session.response_writer, sse_data, session.lock)
    except:
        pass


async def drain_stderr(session):
    """Read child stderr and print to proxy log."""
    try:
        while session.active:
            line = await session.process.stderr.readline()
            if not line:
                break
            text = line.decode('utf-8', errors='replace').rstrip('\n').rstrip('\r')
            if text:
                print(f"[SSE][stderr] {text}", flush=True)
    except:
        pass


async def sse_keepalive(session):
    """Send SSE keepalive comments periodically."""
    try:
        while session.active:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            if not session.active:
                break
            await sse_write(session.response_writer, b": keepalive\n\n", session.lock)
    except:
        pass


def cors_headers():
    """Return common CORS headers as a string for HTTP responses."""
    return (
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
    )


async def handle_sse_connect(client_writer, sse_command):
    """Handle GET /sse — spawn child process and stream SSE events."""
    session_id = uuid.uuid4().hex

    print(f"[SSE] New session {session_id[:8]}… -> {' '.join(sse_command)}", flush=True)

    try:
        process = await asyncio.create_subprocess_exec(
            *sse_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except Exception as e:
        print(f"[SSE][ERROR] Failed to start: {e}", flush=True)
        resp = (
            f"HTTP/1.1 500 Internal Server Error\r\n"
            f"{cors_headers()}"
            f"Content-Length: 0\r\n\r\n"
        )
        client_writer.write(resp.encode())
        await client_writer.drain()
        return

    session = Session(session_id, process, client_writer)
    sessions[session_id] = session

    # Send SSE response headers
    resp_headers = (
        f"HTTP/1.1 200 OK\r\n"
        f"Content-Type: text/event-stream\r\n"
        f"Cache-Control: no-cache\r\n"
        f"Connection: keep-alive\r\n"
        f"{cors_headers()}"
        f"\r\n"
    )
    client_writer.write(resp_headers.encode())
    await client_writer.drain()

    # Send endpoint event
    endpoint_data = f"event: endpoint\ndata: /messages?session_id={session_id}\n\n"
    client_writer.write(endpoint_data.encode())
    await client_writer.drain()

    # Start bridge tasks
    tasks = [
        asyncio.create_task(bridge_stdout_to_sse(session)),
        asyncio.create_task(drain_stderr(session)),
        asyncio.create_task(sse_keepalive(session)),
    ]

    # Wait for child to exit or client disconnect
    try:
        done, pending = await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
    except:
        for t in tasks:
            t.cancel()

    await cleanup_session(session_id)


async def handle_messages_post(client_reader, client_writer, headers_raw):
    """Handle POST /messages?session_id=<id> — forward JSON-RPC to child stdin."""
    # Parse session_id from path (already extracted by caller)
    # headers_raw is the list of header lines (bytes)

    # Find session_id from the stored request path
    # This is passed via the path parameter
    pass


async def handle_client(client_reader, client_writer, sse_command=None):
    """Handle HTTP CONNECT proxy requests and SSE bridge endpoints."""
    try:
        # Read the request line
        request_line = await asyncio.wait_for(client_reader.readline(), timeout=30)
        if not request_line:
            return

        request = request_line.decode('utf-8', errors='ignore').strip()

        # --- SSE Bridge routing (relative paths) ---
        if sse_command is not None:
            # GET /sse
            sse_get = re.match(r'GET\s+/sse\s+HTTP/', request, re.IGNORECASE)
            if sse_get:
                # Read and discard headers
                while True:
                    line = await client_reader.readline()
                    if line in (b'\r\n', b'\n', b''):
                        break
                await handle_sse_connect(client_writer, sse_command)
                return

            # POST /messages?session_id=...
            msg_post = re.match(
                r'POST\s+/messages\?session_id=([a-f0-9]+)\s+HTTP/',
                request, re.IGNORECASE)
            if msg_post:
                session_id = msg_post.group(1)

                # Read headers
                content_length = 0
                while True:
                    line = await client_reader.readline()
                    if line in (b'\r\n', b'\n', b''):
                        break
                    hl = line.decode('utf-8', errors='ignore').lower()
                    if hl.startswith('content-length:'):
                        content_length = int(hl.split(':', 1)[1].strip())

                # Read body
                body = b''
                if content_length > 0:
                    body = await asyncio.wait_for(
                        client_reader.readexactly(content_length), timeout=30)

                session = sessions.get(session_id)
                if session is None or not session.active:
                    resp = (
                        f"HTTP/1.1 404 Not Found\r\n"
                        f"{cors_headers()}"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: 36\r\n\r\n"
                        f'{{"error":"session not found"}}\r\n'
                    )
                    client_writer.write(resp.encode())
                    await client_writer.drain()
                    return

                # Validate JSON
                try:
                    json.loads(body)
                except (json.JSONDecodeError, ValueError):
                    resp = (
                        f"HTTP/1.1 400 Bad Request\r\n"
                        f"{cors_headers()}"
                        f"Content-Type: application/json\r\n"
                        f"Content-Length: 28\r\n\r\n"
                        f'{{"error":"invalid JSON"}}\r\n'
                    )
                    client_writer.write(resp.encode())
                    await client_writer.drain()
                    return

                # Write to child stdin
                try:
                    session.process.stdin.write(body + b'\n')
                    await session.process.stdin.drain()
                except Exception as e:
                    print(f"[SSE][ERROR] stdin write: {e}", flush=True)
                    resp = (
                        f"HTTP/1.1 500 Internal Server Error\r\n"
                        f"{cors_headers()}"
                        f"Content-Length: 0\r\n\r\n"
                    )
                    client_writer.write(resp.encode())
                    await client_writer.drain()
                    return

                resp = (
                    f"HTTP/1.1 202 Accepted\r\n"
                    f"{cors_headers()}"
                    f"Content-Length: 0\r\n\r\n"
                )
                client_writer.write(resp.encode())
                await client_writer.drain()
                return

            # OPTIONS /messages (CORS preflight)
            opts_match = re.match(r'OPTIONS\s+/messages', request, re.IGNORECASE)
            if opts_match:
                # Read and discard headers
                while True:
                    line = await client_reader.readline()
                    if line in (b'\r\n', b'\n', b''):
                        break
                resp = (
                    f"HTTP/1.1 204 No Content\r\n"
                    f"{cors_headers()}"
                    f"\r\n"
                )
                client_writer.write(resp.encode())
                await client_writer.drain()
                return

        # --- Existing proxy logic ---

        # Parse CONNECT request: CONNECT host:port HTTP/1.1
        match = re.match(r'CONNECT\s+([^:]+):(\d+)\s+HTTP/', request, re.IGNORECASE)

        if match:
            # HTTPS CONNECT tunnel
            host, port = match.group(1), int(match.group(2))

            # Read and discard headers
            while True:
                line = await client_reader.readline()
                if line in (b'\r\n', b'\n', b''):
                    break

            print(f"[CONNECT] {host}:{port}", flush=True)

            try:
                # Connect to target
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=30
                )

                # Send success response
                client_writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                await client_writer.drain()

                # Bidirectional tunnel
                await asyncio.gather(
                    pipe(client_reader, remote_writer),
                    pipe(remote_reader, client_writer),
                    return_exceptions=True
                )

            except Exception as e:
                print(f"[ERROR] {host}:{port} - {e}", flush=True)
                client_writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await client_writer.drain()
        else:
            # Regular HTTP request - parse GET/POST etc with absolute URL (proxy)
            match = re.match(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+http://([^/:]+)(?::(\d+))?(/.*)?\s+HTTP/', request, re.IGNORECASE)
            if match:
                method, host, port, path = match.groups()
                port = int(port) if port else 80
                path = path or '/'

                print(f"[{method}] {host}:{port}{path}", flush=True)

                # Read headers
                headers = []
                while True:
                    line = await client_reader.readline()
                    if line in (b'\r\n', b'\n', b''):
                        break
                    # Skip proxy headers
                    if not line.lower().startswith(b'proxy-'):
                        headers.append(line)

                try:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=30
                    )

                    # Forward request
                    remote_writer.write(f'{method} {path} HTTP/1.1\r\n'.encode())
                    remote_writer.write(f'Host: {host}\r\n'.encode())
                    for h in headers:
                        remote_writer.write(h)
                    remote_writer.write(b'\r\n')
                    await remote_writer.drain()

                    # Bidirectional tunnel for response
                    await asyncio.gather(
                        pipe(client_reader, remote_writer),
                        pipe(remote_reader, client_writer),
                        return_exceptions=True
                    )

                except Exception as e:
                    print(f"[ERROR] {host}:{port} - {e}", flush=True)
                    client_writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    await client_writer.drain()
            else:
                print(f"[INVALID] {request[:50]}", flush=True)
                client_writer.write(b'HTTP/1.1 400 Bad Request\r\n\r\n')
                await client_writer.drain()

    except asyncio.TimeoutError:
        pass
    except Exception as e:
        print(f"[ERROR] {e}", flush=True)
    finally:
        try:
            client_writer.close()
            await client_writer.wait_closed()
        except:
            pass


async def main():
    args = parse_args()

    sse_command = args.sse
    # Filter out empty strings from sse_command (argparse REMAINDER quirk)
    if sse_command is not None:
        sse_command = [a for a in sse_command if a]
        if not sse_command:
            print("Error: --sse requires a command", flush=True)
            sys.exit(1)

    handler = functools.partial(handle_client, sse_command=sse_command)
    server = await asyncio.start_server(handler, '127.0.0.1', args.port)

    print("=" * 55, flush=True)
    print("MCP HTTP Proxy + SSE Bridge", flush=True)
    print("=" * 55, flush=True)
    print(f"Listening: 127.0.0.1:{args.port}", flush=True)
    print("", flush=True)
    print("Add to each MCP server env:", flush=True)
    print(f'  "HTTP_PROXY": "http://127.0.0.1:{args.port}"', flush=True)
    print(f'  "HTTPS_PROXY": "http://127.0.0.1:{args.port}"', flush=True)

    if sse_command:
        print("", flush=True)
        print(f"SSE Bridge: {' '.join(sse_command)}", flush=True)
        print(f"  SSE endpoint: http://127.0.0.1:{args.port}/sse", flush=True)

    print("=" * 55, flush=True)

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProxy stopped.", flush=True)
    except OSError as e:
        if e.errno in (48, 98):
            print(f"Error: Port already in use", flush=True)
            sys.exit(1)
        raise
