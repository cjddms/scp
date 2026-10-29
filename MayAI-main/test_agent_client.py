#!/usr/bin/env python3
"""
Fake AI agent: sends one MCP JSON-RPC request to an HTTP MCP server through
the MayAI mitmproxy (default 127.0.0.1:8080) with X-Agent-ID / X-Agent-Token.

    python test_agent_client.py tools/list
    python test_agent_client.py tools/call echo -a text=hi
    python test_agent_client.py tools/call echo -a "text=my password is 1234"
    python test_agent_client.py tools/call echo --token wrong
    python test_agent_client.py tools/list --target 127.0.0.1:9101
    python test_agent_client.py tools/list --no-proxy     # straight to the server
    python test_agent_client.py tools/call echo -a text=hi --stdio test-server   # STDIO transport
    python test_agent_client.py tools/call fetch_page -a page=evil
    python test_agent_client.py resources/read file:///docs/notes.md
    python test_agent_client.py prompts/get summarize -a topic=revenue

Talks to the proxy with http.client directly, so OS proxy-bypass rules for
localhost cannot silently skip MayAI. Stdlib only.
"""

import argparse
import http.client
import json
import os
import subprocess
import sys
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("method", help="JSON-RPC method, e.g. tools/list, tools/call, initialize")
    p.add_argument("tool", nargs="?",
                   help="tool name (tools/call), resource uri (resources/read) or prompt name (prompts/get)")
    p.add_argument("--args", default="{}", help="tool arguments as JSON")
    p.add_argument("-a", "--arg", action="append", default=[], metavar="KEY=VALUE",
                   help="one string tool argument (repeatable; easier than --args in PowerShell)")
    p.add_argument("--agent", default="agent-001")
    p.add_argument("--token", default="secret")
    p.add_argument("--target", default="127.0.0.1:9100", help="MCP server host:port")
    p.add_argument("--proxy", default="127.0.0.1:8080", help="MayAI mitmproxy host:port")
    p.add_argument("--no-proxy", action="store_true")
    p.add_argument("--id", type=int, default=1)
    p.add_argument("--stdio", metavar="SERVER_NAME",
                   help="STDIO mode: launch 'MayAI.py stdio --server-name SERVER_NAME' wrapping "
                        "'test_mcp_server.py --stdio' (policy target = stdio:SERVER_NAME)")
    p.add_argument("--rugpull", action="store_true", help="STDIO mode: start the server with --rugpull")
    o = p.parse_args()

    params: dict = {}
    arguments = json.loads(o.args)
    for item in o.arg:
        key, _, value = item.partition("=")
        arguments[key] = value
    if o.method in ("tools/call", "prompts/get"):
        if not o.tool:
            p.error(f"{o.method} needs a name")
        params = {"name": o.tool, "arguments": arguments}
    elif o.method == "resources/read":
        if not o.tool:
            p.error("resources/read needs a resource uri")
        params = {"uri": o.tool}
    body = json.dumps({"jsonrpc": "2.0", "id": o.id, "method": o.method, "params": params})
    headers = {"Content-Type": "application/json", "Accept": "application/json",
               "X-Agent-ID": o.agent, "X-Agent-Token": o.token}

    if o.stdio:
        return send_stdio(o, body)
    if o.no_proxy:
        host, port = o.target.rsplit(":", 1)
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        conn.request("POST", "/mcp", body, headers)
    else:
        host, port = o.proxy.rsplit(":", 1)
        conn = http.client.HTTPConnection(host, int(port), timeout=10)
        conn.request("POST", f"http://{o.target}/mcp", body, headers)  # absolute URL = proxy form
    resp = conn.getresponse()
    text = resp.read().decode("utf-8", "replace")
    print(f"HTTP {resp.status}")
    try:
        print(json.dumps(json.loads(text), ensure_ascii=False, indent=2))
    except json.JSONDecodeError:
        print(text)
    return 0 if resp.status < 400 else 1


def send_stdio(o: argparse.Namespace, body: str) -> int:
    """Act as an MCP stdio client: spawn the MayAI STDIO proxy (which spawns the
    test server), write one JSON-RPC line, read one reply line."""
    here = Path(__file__).resolve().parent
    server = [sys.executable, str(here / "test_mcp_server.py"), "--stdio"]
    if o.rugpull:
        server.append("--rugpull")
    cmd = [sys.executable, str(here / "MayAI.py"), "stdio", "--server-name", o.stdio, "--", *server]
    env = dict(os.environ, MAYAI_AGENT_ID=o.agent, MAYAI_AGENT_TOKEN=o.token)
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env)
    try:
        proc.stdin.write(body.encode() + b"\n")
        proc.stdin.flush()
        line = proc.stdout.readline().decode("utf-8", "replace")
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
    if not line:
        print("no reply from the STDIO proxy (see the error above)")
        return 1
    reply = json.loads(line)
    print(f"STDIO {'ERROR' if 'error' in reply else 'OK'}")
    print(json.dumps(reply, ensure_ascii=False, indent=2))
    return 1 if "error" in reply else 0


if __name__ == "__main__":
    sys.exit(main())
