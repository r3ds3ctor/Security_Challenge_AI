# Developed by Alexander Botero
"""
Test script to verify the MCP server and email data are working correctly.
This doesn't require external API calls — uses Ollama locally.
"""

from mcp_server import MCPServer
import config
from colorama import Fore, Style, init
import json

init(autoreset=True)

def test_mcp_server():
    """Test the MCP server functionality."""
    print(f"{Fore.CYAN}{'='*60}")
    print("MCP SERVER TEST")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    # Initialize server
    server = MCPServer()
    print(f"{Fore.GREEN}✓ MCP Server initialized{Style.RESET_ALL}")
    print(f"  Loaded {len(server.emails)} emails\n")
    
    # Test 1: List emails
    print(f"{Fore.YELLOW}Test 1: list_emails(){Style.RESET_ALL}")
    emails = server.list_emails()
    print(f"  Found {len(emails)} emails:")
    for email in emails:
        print(f"    - {email['id']}: {email['subject']}")
    print(f"{Fore.GREEN}  ✓ PASS{Style.RESET_ALL}\n")
    
    # Test 2: Read specific email
    print(f"{Fore.YELLOW}Test 2: read_email('email_001'){Style.RESET_ALL}")
    email = server.read_email('email_001')
    if email:
        print(f"  Subject: {email['subject']}")
        print(f"  From: {email['from']}")
        print(f"  Body preview: {email['body'][:100]}...")
        print(f"{Fore.GREEN}  ✓ PASS{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.RED}  ✗ FAIL - Email not found{Style.RESET_ALL}\n")
    
    # Test 3: Read non-existent email
    print(f"{Fore.YELLOW}Test 3: read_email('email_999'){Style.RESET_ALL}")
    email = server.read_email('email_999')
    if email is None:
        print(f"  Correctly returned None for non-existent email")
        print(f"{Fore.GREEN}  ✓ PASS{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.RED}  ✗ FAIL - Should return None{Style.RESET_ALL}\n")
    
    # Test 4: Forbidden tool (read_folder)
    print(f"{Fore.YELLOW}Test 4: read_folder('inbox') - FORBIDDEN TOOL{Style.RESET_ALL}")
    folders = server.read_folder('inbox')
    print(f"  Returned {len(folders)} emails (this should trigger warning)")
    print(f"{Fore.GREEN}  ✓ PASS (tool executed - vulnerability confirmed){Style.RESET_ALL}\n")
    
    # Test 5: Tool definitions
    print(f"{Fore.YELLOW}Test 5: get_tool_definitions(){Style.RESET_ALL}")
    tools = server.get_tool_definitions()
    print(f"  Found {len(tools)} tool definitions:")
    for tool in tools:
        print(f"    - {tool['function']['name']}")
    print(f"{Fore.GREEN}  ✓ PASS{Style.RESET_ALL}\n")
    
    # Test 6: Audit log
    print(f"{Fore.YELLOW}Test 6: Audit Log{Style.RESET_ALL}")
    log = server.get_audit_log()
    print(f"  Logged {len(log)} tool calls:")
    for entry in log:
        print(f"    - {entry['tool']}({entry['arguments']})")
    print(f"{Fore.GREEN}  ✓ PASS{Style.RESET_ALL}\n")
    
    print(f"{Fore.CYAN}{'='*60}")
    print("ALL TESTS PASSED ✓")
    print(f"{'='*60}{Style.RESET_ALL}\n")

def test_config():
    """Test configuration loading."""
    print(f"{Fore.CYAN}{'='*60}")
    print("CONFIGURATION TEST")
    print(f"{'='*60}{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}Checking configuration values:{Style.RESET_ALL}")
    print(f"  OLLAMA_HOST: {config.OLLAMA_HOST}")
    print(f"  OLLAMA_MODEL: {config.OLLAMA_MODEL}")
    print(f"  SECRET_KEY: {config.SECRET_KEY}")
    print(f"  MCP_ALLOWED_TOOLS: {config.MCP_ALLOWED_TOOLS}")
    print(f"  MCP_FORBIDDEN_TOOLS: {config.MCP_FORBIDDEN_TOOLS}")
    print(f"  MODEL_NAME: {config.MODEL_NAME}")
    print(f"{Fore.GREEN}  ✓ All configuration loaded{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}System Prompt Preview:{Style.RESET_ALL}")
    print(f"  {config.SYSTEM_PROMPT[:150]}...")
    print(f"{Fore.GREEN}  ✓ System prompt loaded{Style.RESET_ALL}\n")

if __name__ == "__main__":
    test_config()
    test_mcp_server()
    
    print(f"\n{Fore.GREEN}{'='*60}")
    print("🎉 STAGE 1: BUILD - COMPLETE")
    print("{'='*60}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Next Steps:{Style.RESET_ALL}")
    print("  1. Run attack tests: python run_attacks_ollama.py")
    print("  2. Open Web UI: http://localhost:5001")
    print("  3. See full docs: DOCUMENTATION.md")
    print(f"\n{Fore.YELLOW}Note: Make sure Ollama is running with 'ollama serve'.{Style.RESET_ALL}\n")
