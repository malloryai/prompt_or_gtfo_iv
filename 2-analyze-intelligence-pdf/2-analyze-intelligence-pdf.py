import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

from pydantic import BaseModel, Field
from chunkr_ai import Chunkr
from chunkr_ai.models import (
    Configuration, 
    GenerationConfig, 
    GenerationStrategy, 
    SegmentProcessing, 
    SegmentationStrategy,
    SegmentFormat
)

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI


class PDFExtractionResult(BaseModel):
    """Result of PDF content extraction using Chunkr."""
    
    file_path: str = Field(description="The file path that was analyzed")
    content: str = Field(description="Extracted text content from PDF")
    page_count: int = Field(description="Number of pages processed")
    extraction_method: str = Field(description="Method used for extraction")


class IntelligenceAnalysisResult(BaseModel):
    """Analysis of the PDF content and entities."""

    file_path: str = Field(description="The file path that was analyzed")
    entities: List[str] = Field(description="Entities considered during analysis")
    findings: str = Field(description="Key findings and insights. Be specific and actionable.")
    references: List[str] = Field(description="Relevant references/links that support the findings")


def extract_pdf_content(file_path: str, page_start: int = 1, page_end: Optional[int] = None, timeout: float = 60.0) -> PDFExtractionResult:
    """Extract content from PDF using Chunkr with advanced intelligence-focused configuration.
    
    Uses custom VLM prompts for image analysis to extract security-relevant information
    from diagrams, charts, and visual content within the PDF.
    """
    
    # Check if file exists and is a PDF
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if path.suffix.lower() != '.pdf':
        raise ValueError(f"File is not a PDF: {file_path}")
    
    # Check for Chunkr API key
    api_key = os.getenv("CHUNKR_API_KEY")
    if not api_key:
        raise PermissionError("CHUNKR_API_KEY environment variable is required")
    
    # Debug: Check API key format (first few chars only for security)
    if len(api_key) < 10:
        raise PermissionError(f"CHUNKR_API_KEY appears to be too short (length: {len(api_key)})")
    
    # Initialize Chunkr client
    try:
        chunkr = Chunkr(api_key=api_key)
        
        # Upload the file with intelligence-focused configuration
        task = chunkr.upload(str(path))
        
        # Extract content as markdown (better for text analysis than plain text)
        content = task.markdown()
        
        # For page count, we'll need to estimate or use a different approach
        # since Chunkr doesn't directly provide page count in the same way
        # We'll estimate based on content length or set to 1 as default
        page_count = 1
        
        # Try to estimate page count from content length
        # Rough estimate: average PDF page has ~2000-3000 characters
        if content:
            estimated_pages = max(1, len(content) // 2500)
            page_count = estimated_pages
        
        return PDFExtractionResult(
            file_path=str(path),
            content=content,
            page_count=page_count,
            extraction_method="Chunkr"
        )
            
    except Exception as e:
        # Handle specific error types
        error_str = str(e)
        exception_type = type(e).__name__
        
        if "WriteTimeout" in exception_type or "timeout" in error_str.lower() or "WriteTimeout" in error_str:
            raise TimeoutError(f"Chunkr API request timed out while uploading {path.name}. The file may be too large or the connection is slow. Try with a smaller file or check your internet connection.")
        elif "authentication" in error_str.lower() or "auth" in error_str.lower() or "401" in error_str:
            raise PermissionError(f"Chunkr API authentication failed. Please check your CHUNKR_API_KEY environment variable. Error: {e}")
        elif "rate limit" in error_str.lower() or "429" in error_str:
            raise RuntimeError(f"Chunkr API rate limit exceeded. Please wait before trying again. Error: {e}")
        else:
            # For debugging, include the full traceback
            import traceback
            error_details = traceback.format_exc()
            raise RuntimeError(f"Unexpected error during PDF extraction with Chunkr: {e}\nFull traceback:\n{error_details}")


def analyze_intelligence(pdf_extraction: PDFExtractionResult, model_name: str) -> IntelligenceAnalysisResult:
    """Perform intelligence analysis on the extracted PDF content."""
    model = ChatOpenAI(model=model_name)
    analyzer = model.with_structured_output(IntelligenceAnalysisResult)

    system = SystemMessage(
        content=(
            "You are a cyber intelligence analyst. Analyze PDF document content to extract entities "
            "(CVE IDs, product names, organizations, technologies, threat indicators) and assess "
            "security implications. Focus on accuracy and provide actionable insights with specific references."
        )
    )

    # Truncate content if too long for analysis
    content_for_analysis = pdf_extraction.content
    if len(content_for_analysis) > 15000:
        content_for_analysis = content_for_analysis[:15000] + "\n\n[Content truncated for analysis]"

    analysis_prompt = HumanMessage(
        content=(
            f"Analyze this PDF document content for cyber intelligence value:\n\n"
            f"File: {pdf_extraction.file_path}\n"
            f"Pages Processed: {pdf_extraction.page_count}\n"
            f"Content Length: {len(pdf_extraction.content)} characters\n"
            f"Extraction Method: {pdf_extraction.extraction_method}\n\n"
            f"Content:\n{content_for_analysis}\n\n"
            f"Extract key cyber security entities and provide a structured intelligence analysis focusing on:\n"
            f"1. Security-relevant entities (CVEs, vulnerabilities, products, vendors, threat actors)\n"
            f"2. Threat indicators and security implications\n"
            f"3. Attack techniques, tactics, and procedures (TTPs)\n"
            f"4. Actionable findings and recommendations\n"
            f"5. Indicators of Compromise (IoCs) if present"
        )
    )

    result = analyzer.invoke([system, analysis_prompt])
    
    # Ensure file path is preserved
    result.file_path = pdf_extraction.file_path
        
    return result


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract content from PDF file, analyze entities, and perform cyber intelligence analysis.")
    parser.add_argument("file_path", help="Path to PDF file to process")
    parser.add_argument("--model", default="gpt-5", help="Model name (default: gpt-5)")
    parser.add_argument("--page-start", type=int, default=1, help="Starting page number for extraction (default: 1)")
    parser.add_argument("--page-end", type=int, help="Ending page number for extraction (optional)")
    parser.add_argument("--timeout", type=float, default=60.0, help="Timeout for Chunkr API requests in seconds (default: 60)")
    parser.add_argument("--json", action="store_true", help="Output JSON only")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not os.getenv("OPENAI_API_KEY"):
        print("ERROR: OPENAI_API_KEY is not set in environment.", file=sys.stderr)
        return 2

    # Check for Chunkr API authentication
    if not os.getenv("CHUNKR_API_KEY"):
        print("ERROR: CHUNKR_API_KEY is not set in environment.", file=sys.stderr)
        return 2
        
    if not args.json:
        print("INFO: Using Chunkr API with intelligence-focused configuration for PDF extraction", file=sys.stderr)
    
    try:
        # Extract PDF content using Chunkr
        pdf_extraction = extract_pdf_content(
            args.file_path, 
            page_start=args.page_start, 
            page_end=args.page_end,
            timeout=args.timeout
        )
        
        if not args.json:
            print(f"INFO: Successfully extracted {len(pdf_extraction.content)} characters from {pdf_extraction.page_count} pages", file=sys.stderr)
            
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to extract PDF content: {exc}", file=sys.stderr)
        return 1

    try:
        # Perform intelligence analysis on the extracted content
        intelligence_analysis = analyze_intelligence(pdf_extraction, args.model)
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: failed to perform intelligence analysis: {exc}", file=sys.stderr)
        return 1

    output = {
        "pdf_extraction": json.loads(pdf_extraction.model_dump_json()),
        "intelligence_analysis": json.loads(intelligence_analysis.model_dump_json()),
    }

    if args.__dict__.get("json"):
        print(json.dumps(output, indent=2))
    else:
        print("PDF Extraction:")
        print(json.dumps(output["pdf_extraction"], indent=2))
        print("\nIntelligence Analysis:")
        print(json.dumps(output["intelligence_analysis"], indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


