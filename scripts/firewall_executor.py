#!/usr/bin/env python3
"""Privileged, allowlisted nftables bridge for the unprivileged API."""

import ipaddress
import json
import os
import re
import socket
import socketserver
import subprocess
from pathlib import Path

SOCKET_PATH = os.environ.get("FIREWALL_EXECUTOR_SOCKET", "/run/ids/firewall.sock")
RULE_COMMENT = re.compile(r"^ids-(block|ratelimit)-[A-Za-z0-9_-]+$")


def validate_command(command: object) -> list[str]:
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise ValueError("command must be a list of strings")
    if command == ["nft", "-a", "list", "chain", "inet", "ids", "input"]:
        return command
    if (
        len(command) == 8
        and command[:7] == ["nft", "delete", "rule", "inet", "ids", "input", "handle"]
        and command[7].isdigit()
    ):
        return command

    prefix = ["nft", "insert", "rule", "inet", "ids", "input", "ip", "saddr"]
    if len(command) < len(prefix) or command[:len(prefix)] != prefix:
        raise ValueError("command is not an allowed IDS firewall operation")
    ipaddress.ip_address(command[len(prefix)])
    suffix = command[len(prefix) + 1:]
    if len(suffix) == 4 and suffix[0:2] == ["counter", "drop"]:
        pass
    elif len(suffix) == 7 and suffix[:2] == ["limit", "rate"] and suffix[3:5] == ["counter", "accept"]:
        if not re.fullmatch(r"[1-9][0-9]*/second", suffix[2]):
            raise ValueError("invalid rate limit")
    else:
        raise ValueError("unsupported IDS rule operation")
    if suffix[-2] != "comment" or not RULE_COMMENT.fullmatch(suffix[-1]):
        raise ValueError("invalid IDS rule comment")
    return command


class Executor(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            request = json.loads(self.rfile.readline().decode())
            command = validate_command(request.get("command"))
            result = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False)
            response = {
                "ok": result.returncode == 0,
                "stdout": result.stdout,
                "error": result.stderr if result.returncode else "",
            }
        except Exception as exc:
            response = {"ok": False, "stdout": "", "error": str(exc)}
        self.wfile.write((json.dumps(response) + "\n").encode())


class UnixServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True


def main() -> None:
    path = Path(SOCKET_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    with UnixServer(str(path), Executor) as server:
        os.chmod(path, 0o660)
        server.serve_forever()


if __name__ == "__main__":
    main()