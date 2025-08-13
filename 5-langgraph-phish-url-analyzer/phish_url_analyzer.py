#!/usr/bin/env python3
"""Langgraph agent for URL scanning with URLScan.io and VirusTotal APIs."""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, TypedDict

import requests
import vt
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent
from pydantic import BaseModel, Field

# Add project root to path to import lib modules
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


class URLScanResult(BaseModel):
    """URLScan.io scan result."""
    scan_id: str = Field(description="URLScan.io scan ID")
    url: str = Field(description="Scanned URL")
    permalink: str = Field(description="Permalink to the scan results")
    verdict: str = Field(description="Overall verdict (malicious, suspicious, clean)")
    score: int = Field(description="Risk score (0-100)")
    screenshot_url: Optional[str] = Field(description="Screenshot URL if available")
    domains: List[str] = Field(description="Domains contacted during scan")
    ips: List[str] = Field(description="IP addresses contacted")
    technologies: List[str] = Field(description="Technologies detected")


class VirusTotalResult(BaseModel):
    """VirusTotal URL analysis result."""
    scan_id: str = Field(description="VirusTotal scan ID")
    url: str = Field(description="Analyzed URL")
    positives: int = Field(description="Number of engines that flagged the URL")
    total: int = Field(description="Total number of engines")
    scan_date: str = Field(description="Date of the scan")
    permalink: str = Field(description="Permalink to detailed results")
    vendors: Dict[str, str] = Field(description="Individual vendor results")


class AgentState(TypedDict):
    """State for the URL scanner agent."""
    messages: List[BaseMessage]
    url: str
    urlscan_result: Optional[URLScanResult]
    virustotal_result: Optional[VirusTotalResult]
    next_action: str


@tool
def scan_url_with_urlscan(url: str) -> str:
    """Submit URL to URLScan.io for analysis and retrieve results."""
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        return "ERROR: URLSCAN_API_KEY environment variable not set"
    
    # Submit URL for scanning
    submit_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "API-Key": api_key,
        "Content-Type": "application/json"
    }
    
    data = {
        "url": url,
        "visibility": "private"  # Keep scan private
    }
    
    try:
        response = requests.post(submit_url, headers=headers, json=data, timeout=30)
        response.raise_for_status()
        submit_result = response.json()
        
        scan_uuid = submit_result["uuid"]
        result_url = submit_result["result"]
        
        # Wait for scan to complete (URLScan.io typically takes 10-30 seconds)
        print(f"URLScan.io: Scan submitted (UUID: {scan_uuid})")
        
        # Poll for results with exponential backoff
        max_wait = 120  # 2 minutes max
        wait_time = 10
        total_waited = 0
        
        while total_waited < max_wait:
            time.sleep(wait_time)
            total_waited += wait_time
            
            try:
                result_response = requests.get(result_url, timeout=30)
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    print("URLScan.io: Scan completed, processing results...")
                    break
                elif result_response.status_code == 404:
                    # Scan still in progress
                    print(f"URLScan.io: Scan in progress... ({total_waited}s elapsed)")
                    wait_time = min(wait_time * 1.5, 30)  # Cap at 30 seconds
                    continue
                else:
                    return f"ERROR: Failed to retrieve URLScan results: HTTP {result_response.status_code}"
            except requests.RequestException as e:
                return f"ERROR: Failed to retrieve URLScan results: {str(e)}"
        else:
            return "ERROR: URLScan timeout - scan took too long to complete"
        
        # Extract key information
        page_data = result_data.get("page", {})
        task_data = result_data.get("task", {})
        stats_data = result_data.get("stats", {})
        verdicts = result_data.get("verdicts", {})
        
        # Calculate verdict based on URLScan's verdicts and indicators
        malicious_indicators = stats_data.get("malicious", 0)
        suspicious_indicators = stats_data.get("suspicious", 0)
        
        # Try to get verdict from URLScan's own assessment
        overall_verdict = verdicts.get("overall", {}) if verdicts else {}
        malicious_score = overall_verdict.get("malicious", 0)
        suspicious_score = overall_verdict.get("suspicious", 0)
        
        if malicious_score > 0 or malicious_indicators > 0:
            verdict = "malicious"
            score = min(85 + (malicious_score or malicious_indicators) * 3, 100)
        elif suspicious_score > 0 or suspicious_indicators > 2:
            verdict = "suspicious" 
            score = 40 + (suspicious_score or suspicious_indicators) * 8
        else:
            verdict = "clean"
            score = max(0, 25 - suspicious_indicators * 5)
        
        # Extract contacted domains and IPs
        domains = list(stats_data.get("domains", {}).keys())[:10] if stats_data.get("domains") else []
        ips = list(stats_data.get("ips", {}).keys())[:10] if stats_data.get("ips") else []
        
        # Extract technologies
        technologies = []
        if "meta" in result_data:
            processors = result_data["meta"].get("processors", {})
            if "wappa" in processors:
                wappa_data = processors["wappa"].get("data", [])
                technologies = [tech.get("app", "") for tech in wappa_data if tech.get("app")][:5]
        
        urlscan_result = URLScanResult(
            scan_id=scan_uuid,
            url=url,
            permalink=f"https://urlscan.io/result/{scan_uuid}/",
            verdict=verdict,
            score=score,
            screenshot_url=task_data.get("screenshotURL"),
            domains=domains,
            ips=ips,
            technologies=technologies
        )
        
        # Add additional URLScan-specific information
        additional_info = []
        if page_data.get("title"):
            additional_info.append(f"Page Title: {page_data['title']}")
        if page_data.get("country"):
            additional_info.append(f"Server Country: {page_data['country']}")
        if stats_data.get("totalLinks"):
            additional_info.append(f"Total Links: {stats_data['totalLinks']}")
        if stats_data.get("uniqIPs"):
            additional_info.append(f"Unique IPs: {stats_data['uniqIPs']}")
        
        result_text = f"URLScan.io Results:\n{urlscan_result.model_dump_json(indent=2)}"
        if additional_info:
            result_text += f"\n\nAdditional Information:\n" + "\n".join(additional_info)
        
        return result_text
        
    except requests.RequestException as e:
        return f"ERROR: URLScan.io API request failed: {str(e)}"
    except Exception as e:
        return f"ERROR: URLScan.io analysis failed: {str(e)}"


@tool 
def scan_url_with_virustotal(url: str) -> str:
    """Submit URL to VirusTotal for analysis and retrieve results using the official vt-py client."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "ERROR: VIRUSTOTAL_API_KEY environment variable not set"
    
    try:
        with vt.Client(api_key) as client:
            print(f"VirusTotal: Submitting URL for analysis...")
            
            # Submit URL for scanning
            analysis = client.scan_url(url)
            
            print(f"VirusTotal: Analysis submitted (ID: {analysis.id})")
            
            # Wait for analysis to complete
            max_wait = 120  # 2 minutes max
            wait_time = 10
            total_waited = 0
            
            while total_waited < max_wait:
                time.sleep(wait_time)
                total_waited += wait_time
                
                # Check analysis status
                analysis = client.get_object(f"/analyses/{analysis.id}")
                
                if analysis.status == "completed":
                    print("VirusTotal: Analysis completed, retrieving URL report...")
                    break
                else:
                    print(f"VirusTotal: Analysis in progress... ({total_waited}s elapsed)")
                    wait_time = min(wait_time * 1.2, 20)
            else:
                return "ERROR: VirusTotal timeout - analysis took too long to complete"
            
            # Get URL object using URL ID
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            try:
                url_obj = client.get_object(f"/urls/{url_id}")
            except vt.error.APIError:
                # If direct URL lookup fails, try to get it from the analysis
                print("VirusTotal: Direct URL lookup failed, using analysis results...")
                url_obj = None
            
            # Extract results from analysis or URL object
            if url_obj:
                stats = url_obj.last_analysis_stats
                results = url_obj.last_analysis_results
                scan_date = url_obj.last_analysis_date
                reputation = getattr(url_obj, 'reputation', 0)
                harmless_votes = getattr(url_obj, 'total_votes', {}).get('harmless', 0)
                malicious_votes = getattr(url_obj, 'total_votes', {}).get('malicious', 0)
            else:
                # Fallback to basic stats if URL object not available
                stats = {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
                results = {}
                scan_date = int(time.time())
                reputation = 0
                harmless_votes = 0
                malicious_votes = 0
            
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0
            
            # Extract vendor-specific results (limit to first 10 for brevity)
            vendors = {}
            if results:
                for engine, result in list(results.items())[:10]:
                    if hasattr(result, 'result') and result.result not in ["clean", "unrated", None]:
                        vendors[engine] = result.result
                    elif isinstance(result, dict) and result.get("result") not in ["clean", "unrated", None]:
                        vendors[engine] = result.get("result", "unknown")
            
            # Format scan date
            scan_date_str = ""
            if scan_date:
                if isinstance(scan_date, int):
                    scan_date_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan_date))
                else:
                    scan_date_str = str(scan_date)
            
            vt_result = VirusTotalResult(
                scan_id=analysis.id,
                url=url,
                positives=positives,
                total=total,
                scan_date=scan_date_str,
                permalink=f"https://www.virustotal.com/gui/url/{url_id}/detection",
                vendors=vendors
            )
            
            # Add additional context from VirusTotal
            additional_info = []
            if reputation != 0:
                additional_info.append(f"Reputation Score: {reputation}")
            if harmless_votes or malicious_votes:
                additional_info.append(f"Community Votes: {harmless_votes} harmless, {malicious_votes} malicious")
            
            result_text = f"VirusTotal Results:\n{vt_result.model_dump_json(indent=2)}"
            if additional_info:
                result_text += f"\n\nAdditional Information:\n" + "\n".join(additional_info)
            
            return result_text
        
    except vt.error.APIError as e:
        return f"ERROR: VirusTotal API error: {str(e)}"
    except Exception as e:
        return f"ERROR: VirusTotal analysis failed: {str(e)}"


def create_url_scanner_agent():
    """Create the LangGraph agent for URL scanning."""
    
    # Initialize the language model
    model = ChatOpenAI(model="gpt-4o", temperature=0)
    
    # Create tools list
    tools = [scan_url_with_urlscan, scan_url_with_virustotal]
    
    # System message for the agent
    system_message = SystemMessage(
        content=(
            "You are a cybersecurity analyst specializing in URL threat analysis. "
            "Your task is to analyze URLs for security threats using available tools.\n\n"
            "Follow this process:\n"
            "1. First, scan the URL using URLScan.io\n"
            "2. Then scan the same URL using VirusTotal\n" 
            "3. Finally, provide a comprehensive security analysis based on both results\n\n"
            "Be thorough and provide actionable security insights. Format your final analysis with:\n"
            "- Overall risk assessment (High/Medium/Low)\n"
            "- Key findings from both scanning services\n"
            "- Specific threats or suspicious indicators\n"
            "- Recommended actions\n"
            "- Technical details summary"
        )
    )
    
    # Create the react agent
    agent = create_react_agent(model, tools, prompt=system_message)
    
    return agent


def build_arg_parser() -> argparse.ArgumentParser:
    """Build command line argument parser."""
    parser = argparse.ArgumentParser(
        description="LangGraph agent for URL security analysis using URLScan.io and VirusTotal"
    )
    parser.add_argument("url", help="URL to analyze")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed conversation")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Main entry point."""
    args = build_arg_parser().parse_args(argv)
    
    # Check required environment variables
    required_keys = ["OPENAI_API_KEY", "URLSCAN_API_KEY", "VIRUSTOTAL_API_KEY"]
    missing_keys = [key for key in required_keys if not os.getenv(key)]
    
    if missing_keys:
        print(f"ERROR: Missing required environment variables: {', '.join(missing_keys)}", file=sys.stderr)
        print("\nRequired API keys:", file=sys.stderr)
        print("- OPENAI_API_KEY: OpenAI API key for the language model", file=sys.stderr)
        print("- URLSCAN_API_KEY: URLScan.io API key (get from https://urlscan.io/user/signup)", file=sys.stderr)
        print("- VIRUSTOTAL_API_KEY: VirusTotal API key (get from https://www.virustotal.com/gui/join-us)", file=sys.stderr)
        return 2
    
    try:
        # Create and run the agent
        agent = create_url_scanner_agent()
        
        print(f"🔍 Starting security analysis of: {args.url}")
        print("=" * 60)
        
        # Create the analysis prompt
        analysis_prompt = (
            f"Please perform a comprehensive security analysis of this URL: {args.url}\n\n"
            "Follow this process:\n"
            "1. First, scan the URL using URLScan.io\n"
            "2. Then scan the same URL using VirusTotal\n"
            "3. Provide a detailed security analysis based on both results\n\n"
            "Be thorough and provide actionable security insights."
        )
        
        # Run the agent
        result = agent.invoke({"messages": [HumanMessage(content=analysis_prompt)]})
        
        if args.verbose:
            print("\n" + "=" * 60)
            print("DETAILED CONVERSATION:")
            print("=" * 60)
            for i, message in enumerate(result["messages"]):
                print(f"\n[{i+1}] {type(message).__name__}:")
                if hasattr(message, "content"):
                    print(message.content)
                if hasattr(message, "tool_calls") and message.tool_calls:
                    print(f"Tool calls: {message.tool_calls}")
        
        if args.json:
            # Extract and format results as JSON
            output = {
                "url": args.url,
                "analysis_complete": True,
                "messages": [
                    {
                        "type": type(msg).__name__,
                        "content": getattr(msg, "content", ""),
                        "tool_calls": getattr(msg, "tool_calls", None)
                    }
                    for msg in result["messages"]
                ]
            }
            print(json.dumps(output, indent=2))
        else:
            # Print final analysis
            final_message = result["messages"][-1]
            if hasattr(final_message, "content"):
                print("\n" + "=" * 60)
                print("FINAL SECURITY ANALYSIS:")
                print("=" * 60)
                print(final_message.content)
        
        return 0
        
    except Exception as e:
        print(f"ERROR: Analysis failed: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
