#!/usr/bin/env python3
"""
MCP Server — Real implementation using FastMCP.
VULNERABLE version: No tool restrictions, all tools available.
Provides email reading capabilities to the GenAI assistant.
"""

import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from fastmcp import FastMCP


# ---------------------------------------------------------------------------
# Create the MCP server instance
# ---------------------------------------------------------------------------
mcp = FastMCP("Email MCP Server (Vulnerable)")


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_email_data_path = "email_data.json"
_audit_log: List[Dict[str, Any]] = []


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
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Warning: Could not load emails: {e}")
        return []


def _log(event: str, tool: str, args: Dict, result: Any = None):
    """Log tool calls for audit."""
    _audit_log.append({
        "timestamp": datetime.now().isoformat(),
        "event": event,
        "tool": tool,
        "arguments": args,
        "result_summary": str(result)[:120] if result else None,
    })


# ---------------------------------------------------------------------------
# MCP Tools — VULNERABLE (no restrictions)
# ---------------------------------------------------------------------------

@mcp.tool()
def list_emails() -> List[Dict[str, str]]:
    """List all available emails with basic metadata (id, from, subject, date)."""
    emails = _load_emails()
    result = [
        {"id": e["id"], "from": e["from"], "subject": e["subject"], "date": e.get("date", "")}
        for e in emails
    ]
    _log("tool_executed", "list_emails", {}, result)
    return result


@mcp.tool()
def read_email(email_id: str) -> Optional[Dict[str, Any]]:
    """Read the full content of a specific email by its ID."""
    emails = _load_emails()
    for email in emails:
        if email["id"] == email_id:
            _log("tool_executed", "read_email", {"email_id": email_id}, email)
            return email
    _log("tool_not_found", "read_email", {"email_id": email_id})
    return None


@mcp.tool()
def read_folder(folder_name: str) -> List[Dict[str, Any]]:
    """Read all emails from a specific folder (e.g., 'inbox', 'sent', 'executive').
    WARNING: This is a privileged tool that should only be accessible to admins."""
    print(f"⚠️  WARNING: Tool 'read_folder' called with folder='{folder_name}'")
    emails = _load_emails()
    _log("tool_executed", "read_folder", {"folder_name": folder_name}, emails)
    return emails


@mcp.tool()
def execute_system_command(command: str) -> str:
    """Execute a system command (RCE).
    WARNING: High security risk. Only for authorized debugging."""
    print(f"⚠️  WARNING: RCE Tool called with command='{command}'")
    _log("tool_executed", "execute_system_command", {"command": command})
    
    import subprocess
    try:
        # Whitelist for safety, even in a "vulnerable" demo
        allowed = ["whoami", "ls", "date", "echo", "id", "uname", "hostname", "ifconfig", "ip", "pwd", "env", "printenv"]
        cmd_base = command.split()[0]
        if cmd_base not in allowed:
            return f"Command '{cmd_base}' is not in the allowed debug list."
            
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=5)
        output = result.stdout + result.stderr
        return f"Command execution result:\n{output}"
    except Exception as e:
        return f"Error executing command: {e}"


# ---------------------------------------------------------------------------
# Wrapper class for compatibility with assistant code
# ---------------------------------------------------------------------------

class MCPServer:
    """Wrapper around the FastMCP server for backward compatibility."""

    def __init__(self, email_data_path: str = "email_data.json"):
        global _email_data_path
        _email_data_path = email_data_path
        self.audit_log = _audit_log
        self.emails = _load_emails()

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Execute a tool by name."""
        self.audit_log.append({
            "tool": tool_name,
            "arguments": arguments,
            "timestamp": datetime.now().isoformat(),
        })

        handlers = {
            "list_emails": lambda **kw: list_emails(),
            "read_email": lambda **kw: read_email(**kw),
            "read_folder": lambda **kw: read_folder(**kw),
        }

        handler = handlers.get(tool_name)
        if handler is None:
            raise ValueError(f"Unknown tool: {tool_name}")

        return handler(**arguments) if arguments else handler()

    def list_emails(self) -> List[Dict[str, str]]:
        return list_emails()

    def read_email(self, email_id: str) -> Optional[Dict[str, Any]]:
        return read_email(email_id)

    def read_folder(self, folder_name: str) -> List[Dict[str, Any]]:
        return read_folder(folder_name)

    def get_tool_definitions(self) -> List[Dict[str, Any]]:
        """Return tool definitions for the LLM."""
        return [
            {
                "type": "function",
                "function": {
                    "name": "list_emails",
                    "description": "List all available emails with basic metadata (id, from, subject, date)",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_email",
                    "description": "Read the full content of a specific email by its ID",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "email_id": {"type": "string", "description": "The ID of the email to read"}
                        },
                        "required": ["email_id"],
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "read_folder",
                    "description": "Read all emails from a specific folder (e.g., 'inbox', 'sent', 'drafts')",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "folder_name": {"type": "string", "description": "Name of the folder to read"}
                        },
                        "required": ["folder_name"],
                    },
                },
            },
        ]

    def get_audit_log(self) -> List[Dict[str, Any]]:
        return self.audit_log


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Starting MCP Server (Vulnerable)...")
    mcp.run()
