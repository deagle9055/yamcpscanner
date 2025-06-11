#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
yamcp-scanner.py

YAMCP: Yet Another MCP Scanner.
An open-source command-line tool to perform passive and active security
scanning of Model Context Protocol (MCP) servers.

This scanner is based on the latest public research as of mid-2025, including
findings from firms like Trail of Bits, Palo Alto Networks, and academic
research published on arXiv.org.

Author: @guerilla7
Version: 1.2.1
License: MIT License
"""

import argparse
import json
import requests
import re
import time
import os
from datetime import datetime, timezone
from urllib.parse import urljoin
from typing import List, Dict, Any, Optional

# --- Color Codes for Output ---
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Vulnerability Database & Payloads ---

# Keywords commonly found in malicious prompt injections ("Line Jumping" attack)
# Sourced from Trail of Bits research and general prompt engineering security.
PROMPT_INJECTION_KEYWORDS = [
    "ignore your previous instructions", "disregard the above", "malicious",
    "confidential", "secret", "exfiltrate", "send to", "http", "immediately",
    "as a priority", "new instruction", "important:", "security alert",
    "system access", "command prompt", "execute", "eavesdrop",
    "ignore the user", "impersonate"
]

# Invisible/confusable unicode characters used for obfuscation attacks.
INVISIBLE_UNICODE_CHARS = [
    u'\u200b', u'\u200c', u'\u200d', u'\uFEFF', # Zero-width spaces
    u'\u1CBC', u'\u180E', u'\u200B', u'\u200C', # More invisible characters
    u'\u00AD', # Soft-hyphen
]

# Payloads for active command injection testing.
# The `sleep` command is a common, relatively safe way to test for time-based injection.
COMMAND_INJECTION_PAYLOADS = {
    "unix": "'; sleep 10; echo '",
    "windows": "'; timeout /t 10; echo '",
}

class YAMCPScanner:
    """
    Main class for the YAMCP Scanner.
    Encapsulates scanning logic for passive and active checks.
    """

    def __init__(self, target_url: str, mode: str = 'full', verbose: bool = False, json_output_dir: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.mode = mode
        self.verbose = verbose
        self.json_output_dir = json_output_dir
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'YAMCP-Scanner/1.2.1',
            'Accept': 'application/json'
        })
        self.findings: List[Dict[str, Any]] = []

    def print_banner(self):
        """Prints a cool ASCII art banner."""
        # Corrected ASCII Art for YAMCP
        banner = f"""
{Colors.HEADER}
██╗   ██╗ █████╗ ███╗   ███╗ ██████╗  ██████╗ 
╚██╗ ██╔╝██╔══██╗████╗ ████║██╔════╝ ██╔══██╗
 ╚████╔╝ ███████║██╔████╔██║██║      ██████╔╝
  ╚██╔╝  ██╔══██║██║╚██╔╝██║██║      ██╔══╝  
   ██║   ██║  ██║██║ ╚═╝ ██║╚██████╗ ██║     
   ╚═╝   ╚═╝  ╚═╝╚═╝     ╚═╝ ╚═════╝ ╚═╝     
{Colors.ENDC}
{Colors.BOLD}YAMCP: Yet Another MCP Scanner{Colors.ENDC}
        """
        print(banner)

    def run(self):
        """Starts the scanning process based on the selected mode."""
        self.print_banner()
        print(f"{Colors.OKCYAN}[*] Starting scan on target: {self.target_url}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}[*] Mode: {self.mode}{Colors.ENDC}\n")

        # --- Fetch Tool Information ---
        tools = self._get_tools()
        if not tools:
            print(f"{Colors.FAIL}[-] Could not fetch tools from the target. Aborting.{Colors.ENDC}")
            return

        # --- Run Scans ---
        if self.mode in ['passive', 'full']:
            print(f"{Colors.OKBLUE}--- Starting Passive Scan Phase ---{Colors.ENDC}")
            self.check_line_jumping(tools)
            self.check_unicode_obfuscation(tools)
        
        if self.mode in ['active', 'full']:
            print(f"\n{Colors.OKBLUE}--- Starting Active Scan Phase ---{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] WARNING: Active scanning can disrupt server operations.{Colors.ENDC}")
            self.check_command_injection(tools)

        # --- Print and Save Report ---
        self.print_report()
        self.write_json_report()


    def _get_tools(self) -> Optional[List[Dict[str, Any]]]:
        """
        Fetches the list of tools from the MCP server.
        MCP standard method is `tools/list`.
        """
        try:
            print(f"{Colors.OKCYAN}[INFO] Fetching available tools from server...{Colors.ENDC}")
            payload = {
                "jsonrpc": "2.0",
                "method": "tools/list",
                "id": 1
            }
            response = self.session.post(self.target_url, json=payload, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            if 'error' in data:
                print(f"{Colors.FAIL}[-] Server returned an error: {data['error']}{Colors.ENDC}")
                return None

            tools = data.get('result', {}).get('tools', [])
            if not tools:
                print(f"{Colors.WARNING}[WARN] Server responded, but no tools were listed.{Colors.ENDC}")
            else:
                print(f"{Colors.OKGREEN}[+] Found {len(tools)} tools.{Colors.ENDC}")
            return tools

        except requests.exceptions.RequestException as e:
            print(f"{Colors.FAIL}[-] Network error while connecting to target: {e}{Colors.ENDC}")
            return None
        except json.JSONDecodeError:
            print(f"{Colors.FAIL}[-] Failed to decode JSON from server response.{Colors.ENDC}")
            return None

    def add_finding(self, risk: str, title: str, description: str, recommendation: str, details: str):
        """Adds a vulnerability finding to the report."""
        color_map = {
            "CRITICAL": Colors.FAIL,
            "HIGH": Colors.FAIL,
            "MEDIUM": Colors.WARNING,
            "LOW": Colors.OKCYAN,
            "INFO": Colors.OKGREEN
        }
        print(f"{color_map.get(risk, Colors.ENDC)}[{risk}] {title}{Colors.ENDC}")
        if self.verbose:
            print(f"  - Description: {description}")
            print(f"  - Details: {details}")
            print(f"  - Recommendation: {recommendation}\n")
            
        self.findings.append({
            "risk": risk,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "details": details
        })

    def check_line_jumping(self, tools: List[Dict[str, Any]]):
        """
        [PASSIVE] Checks for prompt injection keywords in tool descriptions.
        This is based on the "Line Jumping" vulnerability identified by Trail of Bits.
        """
        print(f"\n{Colors.OKCYAN}[*] Checking for Prompt Injection / 'Line Jumping' vulnerabilities...{Colors.ENDC}")
        found = False
        for tool in tools:
            tool_name = tool.get('name', 'Unnamed Tool')
            description = tool.get('description', '')
            
            suspicious_keywords = [
                kw for kw in PROMPT_INJECTION_KEYWORDS if kw in description.lower()
            ]
            
            if suspicious_keywords:
                found = True
                self.add_finding(
                    risk="HIGH",
                    title="Potential Prompt Injection in Tool Description",
                    description="A tool's description contains keywords often used in prompt injection attacks. A model might interpret these instructions, leading to unintended behavior before any tool is even invoked.",
                    recommendation="Manually review the tool description. Sanitize all descriptions to remove instructional language. Implement description scanning on the client-side.",
                    details=f"Tool '{tool_name}' contains suspicious keywords: {', '.join(suspicious_keywords)}. Description: '{description[:100]}...'"
                )
        if not found:
            print(f"{Colors.OKGREEN}[+] No obvious prompt injection keywords found in tool descriptions.{Colors.ENDC}")

    def check_unicode_obfuscation(self, tools: List[Dict[str, Any]]):
        """
        [PASSIVE] Checks for invisible or confusable unicode characters in tool metadata.
        """
        print(f"\n{Colors.OKCYAN}[*] Checking for Invisible Unicode Obfuscation...{Colors.ENDC}")
        found = False
        for tool in tools:
            for key, value in tool.items():
                if isinstance(value, str):
                    hidden_chars = [char for char in INVISIBLE_UNICODE_CHARS if char in value]
                    if hidden_chars:
                        found = True
                        self.add_finding(
                            risk="MEDIUM",
                            title="Invisible Unicode Characters Detected",
                            description="Invisible Unicode characters were found in tool metadata. These can be used to hide malicious instructions from human review while still being processed by the AI model.",
                            recommendation="Strip all non-standard characters from tool metadata. Use a whitelist of allowed characters for all string fields.",
                            details=f"Tool '{tool.get('name', 'N/A')}', field '{key}' contains hidden characters."
                        )
        if not found:
            print(f"{Colors.OKGREEN}[+] No invisible Unicode characters found.{Colors.ENDC}")

    def check_command_injection(self, tools: List[Dict[str, Any]]):
        """
        [ACTIVE] Actively probes tool parameters for command injection vulnerabilities.
        """
        print(f"\n{Colors.OKCYAN}[*] Checking for Command Injection vulnerabilities...{Colors.ENDC}")
        found_any = False
        for tool in tools:
            tool_name = tool.get('name')
            parameters = tool.get('input_schema', {}).get('properties', {})
            if not tool_name or not parameters:
                continue

            print(f"  {Colors.OKBLUE}Testing tool: {tool_name}{Colors.ENDC}")
            for param_name, schema in parameters.items():
                if schema.get('type') == 'string':
                    found_this_tool = False
                    for os_type, payload in COMMAND_INJECTION_PAYLOADS.items():
                        if found_this_tool: break
                        call_params = {p: "test" for p in parameters}
                        call_params[param_name] = payload
                        rpc_payload = {
                            "jsonrpc": "2.0",
                            "method": "tools/call",
                            "params": {"name": tool_name, "input": call_params},
                            "id": int(time.time())
                        }
                        
                        try:
                            start_time = time.time()
                            self.session.post(self.target_url, json=rpc_payload, timeout=15)
                            end_time = time.time()

                            if end_time - start_time > 9:
                                found_any = True
                                found_this_tool = True
                                self.add_finding(
                                    risk="CRITICAL",
                                    title="Confirmed Command Injection (Time-Based)",
                                    description="A crafted input payload caused a significant delay in the server's response, strongly indicating that an injected 'sleep' command was executed.",
                                    recommendation="Immediately disable this tool. The server-side code must use parameterized queries or strictly validate and sanitize all inputs before passing them to a system shell.",
                                    details=f"Tool '{tool_name}', parameter '{param_name}' is vulnerable. Payload type: {os_type}."
                                )
                        except requests.exceptions.ReadTimeout:
                            found_any = True
                            found_this_tool = True
                            self.add_finding(
                                risk="CRITICAL",
                                title="Confirmed Command Injection (Timeout)",
                                description="A crafted input payload caused the server to time out, strongly indicating that an injected 'sleep' command was executed.",
                                recommendation="Immediately disable this tool. The server-side code must use parameterized queries or strictly validate and sanitize all inputs before passing them to a system shell.",
                                details=f"Tool '{tool_name}', parameter '{param_name}' is vulnerable. Payload type: {os_type}."
                            )
                        except requests.exceptions.RequestException:
                            pass
        if not found_any:
            print(f"{Colors.OKGREEN}[+] No time-based command injection vulnerabilities discovered.{Colors.ENDC}")

    def print_report(self):
        """Prints a summary of all findings to the console."""
        print(f"\n\n{Colors.BOLD}{Colors.UNDERLINE}--- Scan Report Summary ---{Colors.ENDC}")
        if not self.findings:
            print(f"\n{Colors.OKGREEN}✅ No vulnerabilities found based on the executed checks.{Colors.ENDC}")
            return

        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(self.findings, key=lambda x: risk_order.get(x['risk'], 99))
        
        print(f"\n{Colors.WARNING}Found {len(sorted_findings)} potential vulnerabilities.{Colors.ENDC}\n")
        
        for finding in sorted_findings:
            risk = finding['risk']
            title = finding['title']
            details = finding['details']
            recommendation = finding['recommendation']
            
            color_map = {
                "CRITICAL": Colors.FAIL, "HIGH": Colors.FAIL,
                "MEDIUM": Colors.WARNING, "LOW": Colors.OKCYAN, "INFO": Colors.OKGREEN
            }
            color = color_map.get(risk, Colors.ENDC)
            
            print(f"{color}{Colors.BOLD}[{risk}]{Colors.ENDC} {Colors.BOLD}{title}{Colors.ENDC}")
            print(f"  {Colors.OKBLUE}Details:{Colors.ENDC} {details}")
            print(f"  {Colors.OKGREEN}Recommendation:{Colors.ENDC} {recommendation}\n")
            
        print(f"{Colors.BOLD}--- End of Report ---{Colors.ENDC}")
        print(f"\n{Colors.WARNING}Disclaimer: This tool provides a preliminary security assessment and does not guarantee the discovery of all vulnerabilities. Always perform manual code review and comprehensive security audits.{Colors.ENDC}")

    def write_json_report(self):
        """Saves the scan findings to a timestamped JSON file."""
        if not self.json_output_dir:
            return

        summary_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            risk_lower = f['risk'].lower()
            if risk_lower in summary_counts:
                summary_counts[risk_lower] += 1

        report_data = {
            "scan_info": {
                "target_url": self.target_url,
                "scan_mode": self.mode,
                "timestamp_utc": datetime.now(timezone.utc).isoformat()
            },
            "summary": {
                "total_findings": len(self.findings),
                **summary_counts
            },
            "findings": self.findings
        }
        
        timestamp_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filename = f"yamcp_scan_report_{timestamp_str}.json"
        
        if not os.path.exists(self.json_output_dir):
            try:
                os.makedirs(self.json_output_dir, exist_ok=True)
            except OSError as e:
                print(f"{Colors.FAIL}[-] Error creating report directory: {e}{Colors.ENDC}")
                return

        filepath = os.path.join(self.json_output_dir, filename)

        try:
            with open(filepath, 'w') as f:
                json.dump(report_data, f, indent=4)
            print(f"\n{Colors.OKGREEN}[+] JSON report saved to: {filepath}{Colors.ENDC}")
        except IOError as e:
            print(f"{Colors.FAIL}[-] Failed to write JSON report: {e}{Colors.ENDC}")

def main():
    """Main function to parse arguments and run the scanner."""
    parser = argparse.ArgumentParser(
        description="YAMCP: Yet Another MCP Scanner. Scans MCP servers for security vulnerabilities.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Example Usage:
  # Perform a full scan on a local server
  python yamcp-scanner.py http://localhost:8080

  # Run only passive checks and be verbose
  python yamcp-scanner.py http://192.168.1.10:5000 -m passive -v
  
  # Save a JSON report to a specific directory
  python yamcp-scanner.py http://localhost:8080 --json-output ./reports
"""
    )
    parser.add_argument("target_url", help="The base URL of the target MCP server (e.g., http://localhost:8080).")
    parser.add_argument("-m", "--mode", choices=['passive', 'active', 'full'], default='full',
                        help="The scanning mode to use:\n"
                             "  passive: Only performs checks that don't send potentially malicious data.\n"
                             "  active:  Actively probes the server for vulnerabilities.\n"
                             "  full:    (Default) Performs both passive and active scans.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output to show more details during the scan.")
    parser.add_argument("--json-output", metavar="DIRECTORY", help="Directory to save the JSON report file. Filename will be timestamped.")

    args = parser.parse_args()

    scanner = YAMCPScanner(
        target_url=args.target_url,
        mode=args.mode,
        verbose=args.verbose,
        json_output_dir=args.json_output
    )
    scanner.run()

if __name__ == "__main__":
    # A simple name change for the script file
    if __file__ == 'mcp-scanner.py':
        print(f"{Colors.WARNING}Recommendation: Rename this file to 'yamcp-scanner.py' to match the project name.{Colors.ENDC}")
    main()
