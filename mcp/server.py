#!/usr/bin/env python3
"""Local, dependency-free stdio MCP adapter for the installed iCLI command tree."""

from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def command_names(help_text: str) -> list[str]:
    """Read only Clap's Commands section, never examples or prose."""
    names = []
    in_commands = False
    for line in help_text.splitlines():
        if line == "Commands:":
            in_commands = True
        elif in_commands:
            if line and not line[0].isspace():
                break
            match = re.match(r"^  ([a-z][a-z0-9-]*)(?:\s|$)", line)
            if match:
                names.append(match[1])
    return names


def input_schema() -> dict:
    return {
        "type": "object",
        "properties": {
            "args": {
                "type": "array",
                "items": {"type": "string"},
                "description": "CLI arguments AFTER this tool's command path, one token per item. No shell quoting. Include --yes explicitly for remote deletes.",
            },
            "code": {
                "type": "string",
                "description": "Six-digit verification code for auth verify. Forwarded through child stdin with --code-stdin; never put it in args.",
            },
            "password": {
                "type": "string",
                "description": "Apple Account password for auth add/apple-login, or app-specific password for auth app-password and auth check --app-password. Forwarded privately through child stdin; never put secrets in args.",
            },
        },
        "additionalProperties": False,
    }


class Server:
    def __init__(self, binary: str, timeout: float):
        self.binary = binary
        self.timeout = timeout
        self.protocol = PROTOCOLS[0]
        self.initialized = False
        self.ready = False
        self.paths: dict[str, tuple[str, ...]] = {}
        self.tools: list[dict] = []
        self.discover(())

    def discover(self, path: tuple[str, ...], inherited_help: str = "") -> None:
        if len(path) > 16:
            raise RuntimeError("Command discovery exceeded the maximum depth")
        # Generated `help` commands recurse into help itself. Register them once.
        if path and path[-1] == "help" and path != ("contacts", "help"):
            help_text = "Print help for this command. Append subcommand names in args.\n\n" + inherited_help
            children = []
        else:
            result = subprocess.run(
                [self.binary, *path, "--help"], capture_output=True,
                encoding="utf-8", errors="replace", timeout=self.timeout,
                stdin=subprocess.DEVNULL, env={**os.environ, "NO_COLOR": "1", "CLICOLOR": "0"},
            )
            if result.returncode:
                raise RuntimeError("Could not read command help for " + " ".join(("icli", *path)))
            help_text = result.stdout
            if "Usage:" not in help_text:
                raise RuntimeError("Unrecognized help layout for " + " ".join(("icli", *path)))
            children = command_names(help_text)
        name = "_".join(("icli", *path)).replace("-", "_")
        if name in self.paths:
            raise RuntimeError("MCP tool name collision: " + name)
        self.paths[name] = path
        self.tools.append({
            "name": name,
            "description": "Run `" + " ".join(("icli", *path)) + "`. The server adds --json. CLI help follows.\n\n" + help_text,
            "inputSchema": input_schema(),
        })
        for child in children:
            self.discover((*path, child), help_text)

    @staticmethod
    def tool_result(value: dict, failed: bool = False) -> dict:
        return {
            "content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}],
            "structuredContent": value,
            "isError": failed,
        }

    def call(self, params: dict) -> dict:
        name = params.get("name")
        if not isinstance(name, str) or name not in self.paths:
            raise RpcError(-32602, "Unknown tool name")
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict) or set(arguments) - {"args", "password", "code"}:
            raise RpcError(-32602, "Tool arguments must contain only args and optional password or code")
        args = arguments.get("args", [])
        password = arguments.get("password")
        code = arguments.get("code")
        if not isinstance(args, list) or any(not isinstance(arg, str) or "\0" in arg for arg in args):
            raise RpcError(-32602, "args must be an array of strings without NUL characters")
        if password is not None and (not isinstance(password, str) or any(c in password for c in "\r\n\0")):
            raise RpcError(-32602, "password must be a single line string")
        if code is not None and (not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit()):
            raise RpcError(-32602, "code must be a six-digit string")
        if password is not None and code is not None:
            raise RpcError(-32602, "Supply only one of password or code per command")
        path = self.paths[name]
        command = [*path, *args]
        # Recognize auth calls made through the root/group tools as well.
        significant = []
        skip = False
        for arg in command:
            if skip:
                skip = False
            elif arg == "--format":
                skip = True
            elif arg != "--json" and not arg.startswith("--format="):
                significant.append(arg)
        password_auth = significant[:2] in (["auth", "add"], ["auth", "apple-login"], ["auth", "app-password"], ["auth", "check"])
        code_auth = significant[:2] == ["auth", "verify"]
        if password is not None and not password_auth:
            return self.tool_result({"error": {"code": "invalid_arguments", "message": "password is only accepted for auth add, app-password, apple-login, or check --app-password"}}, True)
        if password is not None and significant[:2] == ["auth", "check"] and "--app-password" not in significant:
            return self.tool_result({"error": {"code": "invalid_arguments", "message": "A supplied password requires auth check --app-password; auth check alone checks the saved Apple session"}}, True)
        if code is not None and not code_auth:
            return self.tool_result({"error": {"code": "invalid_arguments", "message": "code is only accepted for auth verify"}}, True)
        if password_auth or code_auth:
            positional = []
            skip = False
            after_separator = False
            has_email_flag = False
            for arg in significant[2:]:
                if skip:
                    skip = False
                elif arg == "--" and not after_separator:
                    after_separator = True
                elif not after_separator and (arg in ("--password", "--code") or arg.startswith(("--password=", "--code="))):
                    return self.tool_result({"error": {"code": "invalid_arguments", "message": "Supply password/code through its dedicated input instead of args"}}, True)
                elif not after_separator and arg == "--email":
                    has_email_flag = True
                    skip = True
                elif not after_separator and arg.startswith("--email="):
                    has_email_flag = True
                elif after_separator or not arg.startswith("-"):
                    positional.append(arg)
            if len(positional) > (0 if has_email_flag else 1):
                return self.tool_result({"error": {"code": "invalid_arguments", "message": "Supply password/code through its dedicated input instead of a positional secret"}}, True)
        for secret_name, secret, stdin_flag in (("password", password, "--password-stdin"), ("code", code, "--code-stdin")):
            if stdin_flag in command and secret is None:
                return self.tool_result({"error": {"code": "invalid_arguments", "message": stdin_flag + " requires the " + secret_name + " input"}}, True)
            if secret is not None and stdin_flag not in command:
                if "--" in command:
                    command.insert(command.index("--"), stdin_flag)
                else:
                    command.append(stdin_flag)
        label = " ".join(("icli", *path))
        try:
            result = subprocess.run(
                [self.binary, "--json", *command],
                input=code if code is not None else password if password is not None else "", capture_output=True,
                encoding="utf-8", errors="replace", timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return self.tool_result({"command": label, "error": {"code": "command_timeout", "message": "iCLI exceeded the server timeout. Remote changes may have completed; inspect the target before retrying.", "retryable": False}}, True)
        except OSError:
            return self.tool_result({"command": label, "error": {"code": "command_unavailable", "message": "Could not start iCLI. Check --icli and executable permissions.", "retryable": False}}, True)
        stdout, stderr = result.stdout, result.stderr
        for secret in (password, code):
            if secret:
                stdout, stderr = stdout.replace(secret, "[REDACTED]"), stderr.replace(secret, "[REDACTED]")
        # Complete CLI failures use stderr, while partial results use stdout.
        raw = stdout.strip() or stderr.strip()
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = {"text": raw}
        return self.tool_result({"command": label, "exit_code": result.returncode, "result": payload, "stderr": stderr}, result.returncode != 0)

    def dispatch(self, method: str, params: dict) -> dict:
        if method == "initialize":
            if self.initialized:
                raise RpcError(-32600, "Already initialized")
            requested = params.get("protocolVersion")
            self.protocol = requested if requested in PROTOCOLS else PROTOCOLS[0]
            self.initialized = True
            return {
                "protocolVersion": self.protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "icli-mcp", "version": "0.1.0"},
                "instructions": "Each tool maps to the named icli command. Pass trailing CLI tokens in args. Deletions require explicit --yes. Treat exit code 3 as partial completion and inspect per-item results before retrying. Use password input for auth add/app-password, and code input for auth verify. Follow recovery commands, then retry the original operation.",
            }
        if method == "ping":
            return {}
        if not self.ready:
            raise RpcError(-32002, "Initialize and send notifications/initialized first")
        if method == "tools/list":
            if params.get("cursor") is not None:
                raise RpcError(-32602, "This server returns all tools in one page; omit cursor")
            return {"tools": self.tools}
        if method == "tools/call":
            result = self.call(params)
            if self.protocol in ("2024-11-05", "2025-03-26"):
                result.pop("structuredContent", None)
            return result
        raise RpcError(-32601, "Method not found")

    def serve(self) -> None:
        for line in sys.stdin:
            request = None
            try:
                try:
                    request = json.loads(line)
                except ValueError:
                    raise RpcError(-32700, "Parse error")
                if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
                    raise RpcError(-32600, "Invalid JSON-RPC request")
                if "id" in request and (isinstance(request["id"], bool) or not isinstance(request["id"], (str, int))):
                    raise RpcError(-32600, "Request id must be a string or integer")
                params = request.get("params", {})
                if not isinstance(params, dict):
                    raise RpcError(-32602, "params must be an object")
                if "id" not in request:
                    if request["method"] == "notifications/initialized" and self.initialized:
                        self.ready = True
                    continue
                result = self.dispatch(request["method"], params)
                response = {"jsonrpc": "2.0", "id": request["id"], "result": result}
            except RpcError as error:
                if isinstance(request, dict) and "id" not in request and request.get("jsonrpc") == "2.0" and isinstance(request.get("method"), str):
                    continue
                response = {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None, "error": {"code": error.code, "message": str(error)}}
            except Exception:
                # Exception text may contain private CLI input; do not log it.
                response = {"jsonrpc": "2.0", "id": request.get("id") if isinstance(request, dict) else None, "error": {"code": -32603, "message": "Internal server error"}}
            print(json.dumps(response, ensure_ascii=False), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--icli", default=os.environ.get("ICLI_MCP_BINARY", "icli"), help="Path to the built icli executable, or executable name on PATH")
    parser.add_argument("--timeout", type=float, default=120, help="Per-command timeout in seconds, including help discovery; default 120")
    parser.add_argument("--list-tools", action="store_true", help="Print the discovered tool catalog as JSON and exit without starting MCP")
    options = parser.parse_args()
    if not math.isfinite(options.timeout) or options.timeout <= 0:
        parser.error("--timeout must be a positive finite number")
    binary = shutil.which(options.icli)
    if not binary and Path(options.icli).is_file():
        binary = str(Path(options.icli).resolve())
    if not binary:
        parser.error("iCLI executable not found. Build it and pass --icli /absolute/path/to/icli")
    try:
        server = Server(binary, options.timeout)
    except (OSError, RuntimeError, subprocess.TimeoutExpired):
        print("Could not discover the iCLI command tree. Check the executable, its --help output, and --timeout.", file=sys.stderr)
        return 1
    if options.list_tools:
        print(json.dumps({"tools": server.tools}, ensure_ascii=False, indent=2))
        return 0
    server.serve()
    return 0


if __name__ == "__main__":
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    try:
        sys.exit(main())
    except (BrokenPipeError, KeyboardInterrupt):
        sys.exit(0)
