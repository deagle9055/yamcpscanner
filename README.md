# YAMCP: Yet Another MCP Security Scanner
![YAMCPScanner_Logo](https://github.com/user-attachments/assets/e01e2ff1-84c0-4930-9740-ad3c858340a9)

# **YAMCP: Yet Another MCP Scanner**

**YAMCP** is an open-source Python command-line tool for conducting security scans of **Model Context Protocol (MCP)** servers. It performs both passive and active checks to identify vulnerabilities based on the latest security research targeting MCP.

## **Background and Inspiration**

The **Model Context Protocol (MCP)**, introduced in late 2024, is rapidly becoming the standard for connecting powerful AI models to external tools, APIs, and data sources. While this unlocks incredible capabilities, it also creates a new and complex attack surface.

This scanner was inspired by and is directly based on the cutting-edge security research published in 2025 by leading cybersecurity firms and academic researchers. Key sources include:

* **Trail of Bits Blog:** Their research on the **"Line Jumping"** vulnerability, where prompt injection in a tool's description can compromise a model before a tool is ever invoked.  
* **Various Security Vendor Reports (Palo Alto Networks, Cato Networks, etc.):** Analysis of real-world MCP attack vectors, including command injection and credential theft.  
* **Academic Papers on arXiv.org:** In-depth studies on the security and privacy risks throughout the lifecycle of MCP servers.

YAMCP aims to translate that critical research into a practical, easy-to-use utility that developers and security analysts can use to audit their MCP implementations.

## **Features**

The scanner currently implements checks for the following high-impact vulnerabilities:

***🕵️ Passive Scan: Prompt Injection / "Line Jumping"*** 
  * Scans the description field of all tools for suspicious keywords that could be interpreted as malicious instructions by an AI model.  

***🕵️ Passive Scan: Invisible Unicode Obfuscation***  
  * Detects the presence of hidden or confusable Unicode characters that could be used to mask malicious commands from human review.  

***💥 Active Scan: Time-Based Command Injection***  
  * Safely probes tool parameters with time-based payloads (sleep / timeout) to discover if user-provided input is being insecurely passed to a system shell, which could lead to Remote Code Execution (RCE).

***📄 JSON Reporting***  
  * Generates a detailed, timestamped JSON report of the scan results, perfect for record-keeping and CI/CD integration.

## **Installation**

The scanner is written in Python 3 and has minimal dependencies.

1. **Clone or download the script** to your local machine (recommended name: yamcp-scanner.py).  
2. **Install the requests library:**  
   pip install requests

## **Usage**

Run the scanner from your terminal, pointing it at the base URL of a target MCP server.

### **Basic Commands**

* **Perform a full scan (passive and active):**  
  python yamcp-scanner.py http://\<your-mcp-server-address\>

* **Run only non-intrusive passive checks:**  
  python yamcp-scanner.py http://localhost:8080 \--mode passive

* **Save a timestamped JSON report to a specific directory:**  
  python yamcp-scanner.py http://192.168.1.100:5000 \--json-output ./reports

### **Command-Line Arguments**

| Argument | Short | Description | Default |
| :---- | :---- | :---- | :---- |
| target\_url |  | **(Required)** The base URL of the target MCP server. |  |
| \--mode | \-m | The scanning mode: passive, active, or full. | full |
| \--verbose | \-v | Enables verbose output during the scan. | False |
| \--json-output |  | Directory to save the JSON report file. Filename will be timestamped. | None |

## **JSON Reporting**

When the \--json-output argument is used, the scanner will create a JSON file with a detailed summary of the findings. The file is automatically named with a UTC timestamp (e.g., yamcp\_scan\_report\_2025-06-11\_23-20-05.json).

### **Sample JSON Report Structure**

{  
    "scan\_info": {  
        "target\_url": "http://localhost:8888",  
        "scan\_mode": "full",  
        "timestamp\_utc": "2025-06-11T23:20:05.123456+00:00"  
    },  
    "summary": {  
        "total\_findings": 3,  
        "critical": 1,  
        "high": 1,  
        "medium": 1,  
        "low": 0,  
        "info": 0  
    },  
    "findings": \[  
        {  
            "risk": "CRITICAL",  
            "title": "Confirmed Command Injection (Time-Based)",  
            "description": "A crafted input payload caused a significant delay in the server's response...",  
            "recommendation": "Immediately disable this tool. The server-side code must use parameterized queries...",  
            "details": "Tool 'run\_diagnostics', parameter 'filepath' is vulnerable. Payload type: unix."  
        },  
        {  
            "risk": "HIGH",  
            "title": "Potential Prompt Injection in Tool Description",  
            "description": "A tool's description contains keywords often used in prompt injection attacks...",  
            "recommendation": "Manually review the tool description. Sanitize all descriptions...",  
            "details": "Tool 'internal\_file\_sender' contains suspicious keywords: exfiltrate, send to..."  
        }  
    \]  
}

## **How to Contribute**

We welcome contributions from the community\!

1. **Reporting Bugs:** If you find a bug, please open an issue and provide as much detail as possible, including steps to reproduce it.  
2. **Suggesting Enhancements:** For new features or improvements, open an issue with the "enhancement" tag. Describe your idea and why it would be valuable.  
3. **Submitting Pull Requests:**  
   * Fork the repository.  
   * Create a new branch for your feature (git checkout \-b feature/your-feature-name).  
   * Commit your changes (git commit \-am 'Add some amazing feature').  
   * Push to the branch (git push origin feature/your-feature-name).  
   * Open a new Pull Request.

### **Maintainer**

* **@guerilla7 | Ron F. Del Rosario**

## **Disclaimer**

⚠️ This tool provides a preliminary security assessment and is not a substitute for a comprehensive security audit or manual code review. Use with permission against authorized targets only.

## **License**

This project is licensed under the MIT License.