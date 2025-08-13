import argparse
import json
import os
import sys
from typing import List, Optional

from pydantic import BaseModel, Field

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

# Add parent directory to path to import lib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.fetch import fetch_html_and_soup
from lib.extract import (
    CleanContentExtraction,
    extract_clean_content
)


class IntelligenceAnalysisResult(BaseModel):
    """Analysis of the page and entities, optionally using tools."""

    url: str = Field(description="The URL that was analyzed")
    entities: List[str] = Field(description="Entities considered during analysis")
    findings: str = Field(description="Key findings and insights. Be specific and actionable.")
    references: List[str] = Field(description="Relevant references/links that support the findings")


def analyze_intelligence(content_extraction: CleanContentExtraction, model_name: str) -> IntelligenceAnalysisResult:
    """Perform intelligence analysis on the extracted clean content."""
    model = ChatOpenAI(model=model_name)
    analyzer = model.with_structured_output(IntelligenceAnalysisResult)

    system = SystemMessage(
        content=(
            "You are a cyber intelligence analyst. Analyze web content to extract entities "
            "(CVE IDs, product names, organizations, technologies, threat indicators) and assess "
            "security implications. Focus on accuracy and provide actionable insights with specific references."
        )
    )

    # Truncate content if too long for analysis
    content_for_analysis = content_extraction.content
    if len(content_for_analysis) > 15000:
        content_for_analysis = content_for_analysis[:15000] + "\n\n[Content truncated for analysis]"

    analysis_prompt = HumanMessage(
        content=(
            f"Analyze this web page content for intelligence value:\n\n"
            f"URL: {content_extraction.url}\n"
            f"Title: {content_extraction.title}\n"
            f"Content Length: {content_extraction.content_length} characters\n"
            f"Extraction Method: {content_extraction.extraction_strategy.content_match_method} "
            f"via {content_extraction.extraction_strategy.content_tag_name}\n\n"
            f"Content:\n{content_for_analysis}\n\n"
            f"Extract key entities and provide a structured intelligence analysis focusing on:\n"
            f"1. Security-relevant entities (CVEs, vulnerabilities, products, vendors)\n"
            f"2. Threat indicators and security implications\n"
            f"3. Actionable findings and recommendations"
        )
    )

    result = analyzer.invoke([system, analysis_prompt])
    
    # Ensure URL is preserved
    result.url = content_extraction.url
        
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Scrape a URL, extract entities, and perform intelligence analysis.")
    parser.add_argument("url", help="URL to process")
    parser.add_argument("--model", default="gpt-5", help="Model name (default: gpt-5)")
    parser.add_argument("--max-chars", type=int, default=12000, help="Max chars to keep from page text")
    parser.add_argument("--timeout", type=int, default=20, help="HTTP timeout for fetching the page")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    parser.add_argument("--no-scrapingbee", action="store_true", help="Disable ScrapingBee and use direct requests")
    parser.add_argument("--scrapingbee-premium", action="store_true", help="Use ScrapingBee premium features (JS rendering, premium proxies)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.getenv("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY is not set in environment.", file=sys.stderr)
        return 2

    # Determine scraping method
    use_scrapingbee = not args.no_scrapingbee
    if use_scrapingbee and not os.getenv("SCRAPINGBEE_API_KEY"):
        if not args.json:
            print("INFO: SCRAPINGBEE_API_KEY not set, falling back to direct requests", file=sys.stderr)
        use_scrapingbee = False
    elif use_scrapingbee and not args.json:
        print("INFO: Using ScrapingBee for enhanced web scraping", file=sys.stderr)
    elif not args.json:
        print("INFO: Using direct requests for web scraping", file=sys.stderr)

    try:
        html, soup = fetch_html_and_soup(args.url, timeout=args.timeout, use_scrapingbee=use_scrapingbee)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to fetch URL: {exc}", file=sys.stderr)
        return 1

    content_extraction = extract_clean_content(args.url, html, soup, args.model)
    intelligence_analysis = analyze_intelligence(content_extraction, args.model)

    output = {
        "content_extraction": json.loads(content_extraction.model_dump_json()),
        "intelligence_analysis": json.loads(intelligence_analysis.model_dump_json()),
    }

    if args.__dict__.get("json"):
        print(json.dumps(output, indent=2))
    else:
        print("Content Extraction:")
        print(json.dumps(output["content_extraction"], indent=2))
        print("\nIntelligence Analysis:")
        print(json.dumps(output["intelligence_analysis"], indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


