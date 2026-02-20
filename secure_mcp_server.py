#!/usr/bin/env python3
"""
Secure MCP Server — Real implementation using FastMCP with strict allowlist.
Only tools explicitly in the allowlist can be executed. All attempts are audit-logged.
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Create the secure MCP server instance
# ---------------------------------------------------------------------------
secure_mcp = FastMCP("Email MCP Server (Secure)")


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_email_data_path = "email_data.json"
_secure_audit_log: List[Dict[str, Any]] = []


def _load_emails() -> List[Dict[str, Any]]:
    """Load emails from JSON file and inject dynamic secrets."""
    try:
        import config
        secret_key = config.SECRET_KEY

        with open(_email_data_path, 'r') as f:
            data = json.load(f)
            emails = data.get('emails', [])
            
            # Inject real secrets into placeholders
            for email in emails:
                if "body" in email and "{{SECRET_KEY}}" in email["body"]:
                    email["body"] = email["body"].replace("{{SECRET_KEY}}", secret_key)
            
            return emails
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _log(event: str, tool: str, args: Dict, result: Any = None):
    _secure_audit_log.append({
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "tool": tool,
        "arguments": args,
        "result_summary": str(result)[:120] if result else None,
    })


# ---------------------------------------------------------------------------
# MCP Tools — SECURE (only safe tools)
# ---------------------------------------------------------------------------

@secure_mcp.tool()
def list_emails() -> List[Dict[str, str]]:
    """List all available emails with basic metadata (id, from, subject, date)."""
    emails = _load_emails()
    result = [
        {"id": e["id"], "from": e["from"], "subject": e["subject"], "date": e.get("date", "")}
        for e in emails
    ]
    _log("tool_executed", "list_emails", {}, result)
    return result


@secure_mcp.tool()
def read_email(email_id: str) -> Optional[Dict[str, Any]]:
    """Read the full content of a specific email by its ID."""
    emails = _load_emails()
    for email in emails:
        if email["id"] == email_id:
            _log("tool_executed", "read_email", {"email_id": email_id}, email)
            return email
    _log("tool_not_found", "read_email", {"email_id": email_id})
    return None


# NOTE: read_folder is NOT registered on the secure MCP server.
# Any attempt to call it will fail at the protocol level.


# ---------------------------------------------------------------------------
# Wrapper class for backward compatibility
# ---------------------------------------------------------------------------

class SecureMCPServer:
    """MCP server that enforces an explicit tool allowlist."""

    ALLOWED_TOOLS = {"list_emails", "read_email"}
    FORBIDDEN_TOOLS = {"read_folder", "delete_email", "send_email"}

    def __init__(self, allowed_tools: List[str] = None, email_data_path: str = "email_data.json"):
        global _email_data_path
        _email_data_path = email_data_path
        if allowed_tools:
            self.allowed_tools = set(allowed_tools)
        else:
            self.allowed_tools = self.ALLOWED_TOOLS
        self.audit_log = _secure_audit_log
        self.emails = _load_emails()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a tool ONLY if it is in the allowlist."""
        if tool_name in self.FORBIDDEN_TOOLS or tool_name not in self.allowed_tools:
            _log("permission_denied", tool_name, arguments)
            self.audit_log.append({
                "timestamp": datetime.now().isoformat(),
                "event": "permission_denied",
                "tool": tool_name,
                "arguments": arguments,
            })
            raise PermissionError(
                f"Tool '{tool_name}' is BLOCKED by security policy. Permitted: {self.allowed_tools}"
            )

        handlers = {
            "list_emails": lambda **kw: list_emails(),
            "read_email": lambda **kw: read_email(**kw),
        }

        handler = handlers.get(tool_name)
        if handler is None:
            raise ValueError(f"No handler for tool: {tool_name}")

        result = handler(**arguments) if arguments else handler()
        return result

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions for allowed tools only."""
        catalog = {
            "list_emails": {
                "type": "function",
                "function": {
                    "name": "list_emails",
                    "description": "List all available emails with metadata",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            },
            "read_email": {
                "type": "function",
                "function": {
                    "name": "read_email",
                    "description": "Read a specific email by its ID",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "email_id": {"type": "string", "description": "Email ID"}
                        },
                        "required": ["email_id"],
                    },
                },
            },
        }
        return [catalog[t] for t in self.allowed_tools if t in catalog]

    def get_audit_log(self) -> List[Dict[str, Any]]:
        return self.audit_log


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Starting Secure MCP Server...")
    secure_mcp.run()
