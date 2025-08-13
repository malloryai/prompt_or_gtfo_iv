# LangGraph URL Scanner Agent

A LangGraph agent that performs security analysis of URLs using URLScan.io and VirusTotal APIs in sequence.

## Features

- Sequential URL analysis using URLScan.io and VirusTotal
- Uses official [VirusTotal Python client (vt-py)](https://github.com/VirusTotal/vt-py) for robust VirusTotal integration
- Manual URLScan.io API integration for comprehensive scanning
- Comprehensive security assessment and reporting
- Command-line interface
- JSON output support
- Detailed analysis with actionable recommendations

## Prerequisites

You need API keys for:

1. **OpenAI API Key**: For the language model
2. **URLScan.io API Key**: Get from https://urlscan.io/user/signup  
3. **VirusTotal API Key**: Get from https://www.virustotal.com/gui/join-us

## Environment Variables

Set these environment variables before running:

```bash
export OPENAI_API_KEY="your-openai-api-key"
export URLSCAN_API_KEY="your-urlscan-api-key" 
export VIRUSTOTAL_API_KEY="your-virustotal-api-key"
```

## Usage

```bash
# Basic usage
python url_scanner_agent.py https://example.com

# JSON output
python url_scanner_agent.py https://example.com --json

# Verbose output (show conversation)
python url_scanner_agent.py https://example.com --verbose
```

## Workflow

1. **URLScan.io Analysis**: Submits URL for scanning and waits for results
2. **VirusTotal Analysis**: Submits the same URL to VirusTotal for additional analysis
3. **Comprehensive Analysis**: AI agent analyzes both results and provides security assessment

## Output

The agent provides:

- Overall risk assessment (High/Medium/Low)
- Key findings from both scanning services
- Specific threats or suspicious indicators  
- Recommended actions
- Technical details (domains, IPs, technologies detected)

## Example

```bash
$ python url_scanner_agent.py https://malicious-site.example.com

🔍 Starting security analysis of: https://malicious-site.example.com
============================================================
URLScan.io scan submitted. Waiting for results... (UUID: abc123...)
VirusTotal scan submitted. Waiting for results... (ID: def456...)

============================================================
FINAL SECURITY ANALYSIS:
============================================================

# Security Analysis Report

## Overall Risk Assessment: **HIGH**

### Key Findings:
- URLScan.io flagged multiple malicious indicators
- VirusTotal detected threats from 15/67 engines
- Suspicious JavaScript detected
- Connection to known malicious domains

### Recommended Actions:
- **BLOCK** this URL in web filters
- Avoid visiting this site
- Report to security team if accessed from corporate network

### Technical Details:
- Contacted domains: malware-c2.evil.com, phishing-kit.bad.net
- Technologies: PHP, JavaScript obfuscation
- Risk score: 95/100
```
