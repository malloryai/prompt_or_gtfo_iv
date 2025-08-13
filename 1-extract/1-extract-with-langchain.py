import argparse
import json
import os
import re
import sys
from typing import List, Optional

import requests
from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI


class HtmlExtractionStrategy(BaseModel):
    """Strategy for extracting content from HTML."""
    content_tag_name: str = Field(description="HTML tag name for main content (e.g., 'article', 'main', 'div')")
    content_tag_class: Optional[str] = Field(description="CSS class name for content extraction", default=None)
    content_tag_id: Optional[str] = Field(description="HTML id attribute for content extraction", default=None)
    content_match_method: str = Field(
        description="Method to match content: 'id', 'class', 'tag', or 'fallback'",
        default="fallback"
    )


class CleanContentExtraction(BaseModel):
    """Clean content extracted from a web page, focused purely on content quality."""
    
    url: str = Field(description="The URL that was scraped")
    title: str = Field(description="The page title")
    content: str = Field(description="The cleaned, main content text from the page")
    content_length: int = Field(description="Length of the extracted content in characters")
    extraction_strategy: HtmlExtractionStrategy = Field(
        description="The HTML extraction strategy that was used"
    )
    

class IntelligenceAnalysisResult(BaseModel):
    """Analysis of the page and entities, optionally using tools."""

    url: str = Field(description="The URL that was analyzed")
    entities: List[str] = Field(description="Entities considered during analysis")
    findings: str = Field(description="Key findings and insights. Be specific and actionable.")
    references: List[str] = Field(description="Relevant references/links that support the findings")


def fetch_html_and_soup(url: str, timeout: int = 20, use_scrapingbee: bool = True) -> tuple[str, BeautifulSoup]:
    """Fetch URL and return both raw HTML and BeautifulSoup object."""
    
    if use_scrapingbee and os.getenv("SCRAPINGBEE_API_KEY"):
        # Use ScrapingBee API for better scraping
        scrapingbee_url = "https://app.scrapingbee.com/api/v1/"
        params = {
            "api_key": os.getenv("SCRAPINGBEE_API_KEY"),
            "url": url,
            "render_js": "true",  # Enable JavaScript rendering
            "premium_proxy": "true",  # Use premium proxies for better success rate
            "country_code": "us",  # Use US proxies
        }
        
        response = requests.get(scrapingbee_url, params=params, timeout=timeout)
        response.raise_for_status()
        
        if response.status_code != 200:
            raise Exception(f"ScrapingBee API error: {response.status_code}")
            
        html = response.text
    else:
        # Fallback to direct requests
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        }
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        html = response.text
    
    soup = BeautifulSoup(html, "html.parser")
    
    # Remove script/style for cleaner analysis
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    
    return html, soup


def truncate_html_for_model(html: str, max_chars: int = 8000) -> str:
    """Truncate HTML for model input while preserving structure."""
    if len(html) <= max_chars:
        return html
    return html[:max_chars] + "\n\n<!-- [HTML truncated for model input] -->"


def extract_content_with_strategy(soup: BeautifulSoup, strategy: HtmlExtractionStrategy) -> Optional[str]:
    """Extract content using the provided strategy."""
    extracted_content = None
    
    if strategy.content_match_method == "id" and strategy.content_tag_id:
        extracted_content = soup.find(strategy.content_tag_name, id=strategy.content_tag_id)
    elif strategy.content_match_method == "class" and strategy.content_tag_class:
        # Split class on space for multiple classes
        class_list = strategy.content_tag_class.split()
        extracted_content = soup.find(strategy.content_tag_name, class_=class_list)
    elif strategy.content_match_method == "tag":
        extracted_content = soup.find(strategy.content_tag_name)
    else:
        # Fallback to simple text extraction
        extracted_content = soup
    
    if extracted_content is None:
        return None
        
    try:
        return extracted_content.get_text(separator="\n").strip()
    except AttributeError:
        return None


def determine_extraction_strategy(html: str, model_name: str) -> HtmlExtractionStrategy:
    """Use LLM to determine the best HTML extraction strategy."""
    model = ChatOpenAI(model=model_name)
    strategy_extractor = model.with_structured_output(HtmlExtractionStrategy)
    
    prompt = (
        "As an expert in HTML and web scraping, analyze this HTML and determine the best "
        "strategy to extract the main content. Look for semantic tags like <article>, <main>, "
        "or common content containers with meaningful class names or IDs. "
        "Choose the most specific and reliable method."
    )
    
    truncated_html = truncate_html_for_model(html)
    message = HumanMessage(content=f"{prompt}\n\nHTML:\n{truncated_html}")
    
    return strategy_extractor.invoke([message])


def extract_clean_content(page_url: str, html: str, soup: BeautifulSoup, model_name: str) -> CleanContentExtraction:
    """Extract clean content using LLM-guided HTML parsing strategy."""
    # Step 1: Determine extraction strategy
    strategy = determine_extraction_strategy(html, model_name)
    
    # Step 2: Extract content using the strategy
    extracted_text = extract_content_with_strategy(soup, strategy)
    
    # Step 3: Fallback to full page text if strategy fails
    if not extracted_text:
        extracted_text = soup.get_text(separator="\n")
        strategy.content_match_method = "fallback"
        strategy.content_tag_name = "body"
    
    # Clean up text - be more aggressive about cleaning
    # Remove excessive whitespace
    extracted_text = re.sub(r"\n{3,}", "\n\n", extracted_text)
    extracted_text = re.sub(r"[ \t]{2,}", " ", extracted_text)  # Multiple spaces/tabs to single space
    extracted_text = re.sub(r"\n\s*\n", "\n\n", extracted_text)  # Clean up empty lines with spaces
    extracted_text = extracted_text.strip()
    
    # Get title
    title_tag = soup.find("title")
    title_text = title_tag.get_text().strip() if title_tag else "No Title"
    
    # Create clean extraction result
    result = CleanContentExtraction(
        url=page_url,
        title=title_text,
        content=extracted_text,
        content_length=len(extracted_text),
        extraction_strategy=strategy
    )
        
    return result


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


