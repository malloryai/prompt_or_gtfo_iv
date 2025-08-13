"""Web content fetching utilities with ScrapingBee support."""

import os

import requests
from bs4 import BeautifulSoup


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
