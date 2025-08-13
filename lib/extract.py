"""Content extraction utilities with LLM-guided HTML parsing."""

import re
from typing import Optional

from bs4 import BeautifulSoup
from pydantic import BaseModel, Field

from langchain_core.messages import HumanMessage
from langchain_openai import ChatOpenAI

from .fetch import truncate_html_for_model


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
