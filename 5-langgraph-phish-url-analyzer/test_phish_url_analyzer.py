#!/usr/bin/env python3
"""Test script for the URL scanner agent."""

import os
import sys

# Add project root to path to import lib modules  
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def test_import():
    """Test that we can import the main module."""
    try:
        from phish_url_analyzer import (
            URLScanResult,
            VirusTotalResult, 
            AgentState,
            scan_url_with_urlscan,
            scan_url_with_virustotal,
            create_url_scanner_agent,
            build_arg_parser
        )
        print("✅ Successfully imported all components")
        return True
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False

def test_argument_parser():
    """Test the argument parser."""
    try:
        from phish_url_analyzer import build_arg_parser
        
        parser = build_arg_parser()
        
        # Test with valid arguments
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"
        assert not args.json
        assert not args.verbose
        
        # Test with all flags
        args = parser.parse_args(["https://example.com", "--json", "--verbose"])
        assert args.url == "https://example.com"
        assert args.json
        assert args.verbose
        
        print("✅ Argument parser tests passed")
        return True
    except Exception as e:
        print(f"❌ Argument parser test failed: {e}")
        return False

def test_models():
    """Test the Pydantic models."""
    try:
        from phish_url_analyzer import URLScanResult, VirusTotalResult
        
        # Test URLScanResult
        urlscan_data = {
            "scan_id": "test-id",
            "url": "https://example.com", 
            "permalink": "https://urlscan.io/result/test-id/",
            "verdict": "clean",
            "score": 10,
            "screenshot_url": "https://urlscan.io/screenshots/test.png",
            "domains": ["example.com"],
            "ips": ["93.184.216.34"],
            "technologies": ["Apache"]
        }
        
        urlscan_result = URLScanResult(**urlscan_data)
        assert urlscan_result.url == "https://example.com"
        assert urlscan_result.verdict == "clean"
        
        # Test VirusTotalResult
        vt_data = {
            "scan_id": "test-vt-id",
            "url": "https://example.com",
            "positives": 0,
            "total": 67,
            "scan_date": "2024-01-01 12:00:00",
            "permalink": "https://www.virustotal.com/gui/url/test/detection",
            "vendors": {}
        }
        
        vt_result = VirusTotalResult(**vt_data)
        assert vt_result.url == "https://example.com"
        assert vt_result.positives == 0
        
        print("✅ Pydantic models tests passed")
        return True
    except Exception as e:
        print(f"❌ Pydantic models test failed: {e}")
        return False

def test_tool_functions_without_api():
    """Test tool functions without making actual API calls."""
    try:
        from url_scanner_agent import scan_url_with_urlscan, scan_url_with_virustotal
        
        # Test without API keys (should return error messages)
        old_urlscan_key = os.environ.get("URLSCAN_API_KEY")
        old_vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
        
        # Remove keys temporarily
        if "URLSCAN_API_KEY" in os.environ:
            del os.environ["URLSCAN_API_KEY"]
        if "VIRUSTOTAL_API_KEY" in os.environ:
            del os.environ["VIRUSTOTAL_API_KEY"]
        
        # Test URLScan without key
        result = scan_url_with_urlscan("https://example.com")
        assert "ERROR: URLSCAN_API_KEY environment variable not set" in result
        
        # Test VirusTotal without key  
        result = scan_url_with_virustotal("https://example.com")
        assert "ERROR: VIRUSTOTAL_API_KEY environment variable not set" in result
        
        # Restore keys
        if old_urlscan_key:
            os.environ["URLSCAN_API_KEY"] = old_urlscan_key
        if old_vt_key:
            os.environ["VIRUSTOTAL_API_KEY"] = old_vt_key
        
        print("✅ Tool function tests passed")
        return True
    except Exception as e:
        print(f"❌ Tool function test failed: {e}")
        return False

def test_agent_creation():
    """Test that we can create the agent without errors."""
    try:
        # Skip if OpenAI key not available
        if not os.getenv("OPENAI_API_KEY"):
            print("⚠️  Skipping agent creation test (OPENAI_API_KEY not set)")
            return True
            
        from url_scanner_agent import create_url_scanner_agent
        
        agent = create_url_scanner_agent()
        assert agent is not None
        
        print("✅ Agent creation test passed")
        return True
    except Exception as e:
        print(f"❌ Agent creation test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("🧪 Running URL Scanner Agent Tests")
    print("=" * 50)
    
    tests = [
        test_import,
        test_argument_parser,
        test_models,
        test_tool_functions_without_api,
        test_agent_creation
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    raise SystemExit(main())
