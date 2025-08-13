#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sigma Detection Rule Generator using LangChain

This tool generates Sigma detection rules based on exploit analysis. It can either:
1. Use existing analysis results from 3-analyze-exploit.py (JSON format)
2. Run new analysis using the exploit analyzer
3. Analyze exploit files directly

The generated Sigma rules follow the standard Sigma format and include:
- Detection patterns for the specific exploit
- IOCs and behavioral indicators
- Network and system-level detections
- Multiple log source coverage
"""

import os
import sys

# Disable LangSmith tracing to prevent 403 errors
os.environ["LANGCHAIN_TRACING_V2"] = "false"
import argparse
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

# Import from the exploit analyzer
sys.path.append(str(Path(__file__).parent.parent / "3-analyze-exploit"))
try:
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "exploit_analyzer", 
        Path(__file__).parent.parent / "3-analyze-exploit" / "3-analyze-exploit.py"
    )
    exploit_analyzer_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exploit_analyzer_module)
    ExploitAnalyzer = exploit_analyzer_module.ExploitAnalyzer
    ExploitAnalysis = exploit_analyzer_module.ExploitAnalysis
except Exception as e:
    print(f"Warning: Could not import ExploitAnalyzer: {e}. Direct analysis may not work.")
    ExploitAnalyzer = None
    ExploitAnalysis = None

@dataclass
class SigmaRule:
    """Represents a Sigma detection rule"""
    title: str
    id: str
    status: str
    description: str
    references: List[str]
    author: str
    date: str
    modified: str
    tags: List[str]
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    falsepositives: List[str]
    level: str


class SigmaRuleOutput(BaseModel):
    """Structured output for Sigma rule generation"""
    rules: List[Dict[str, Any]] = Field(description="List of Sigma detection rules")
    rule_count: int = Field(description="Number of rules generated")
    coverage_areas: List[str] = Field(description="Areas of detection coverage")
    confidence_score: float = Field(description="Confidence in detection effectiveness (0.0-1.0)")

class SigmaRuleGenerator:
    """Generates Sigma detection rules using LangChain and OpenAI"""
    
    def __init__(self, model_name: str = "gpt-4o-mini", temperature: float = 0.1):
        self.llm = ChatOpenAI(
            model=model_name,
            temperature=temperature
        )
        self.parser = JsonOutputParser(pydantic_object=SigmaRuleOutput)
        self._setup_generation_chain()
    
    def _setup_generation_chain(self):
        """Set up the LangChain Sigma rule generation chain"""
        
        prompt_template = """
You are a cybersecurity expert specializing in creating Sigma detection rules. Your task is to generate comprehensive Sigma detection rules based on the provided exploit analysis.

EXPLOIT ANALYSIS:
{analysis_data}

Based on this exploit analysis, generate Sigma detection rules that would detect this attack. Consider:

1. **Network-based Detection**: HTTP requests, URL patterns, user agents
2. **System-based Detection**: File access patterns, process execution
3. **Application-based Detection**: Error patterns, log signatures
4. **Behavioral Detection**: Attack patterns and sequences

For each Sigma rule, include:
- **title**: Descriptive title of what the rule detects
- **id**: Unique UUID for the rule
- **status**: "test" for new rules
- **description**: Clear description of the detection logic
- **references**: CVE, exploit sources, documentation
- **author**: "AI-Generated Detection"
- **date**: Current date
- **modified**: Current date
- **tags**: Relevant MITRE ATT&CK techniques and general tags
- **logsource**: Appropriate log source (webserver, application, system, etc.)
- **detection**: Detection logic with selection criteria and condition
- **falsepositives**: Potential false positive scenarios
- **level**: "high", "medium", or "critical" based on severity

Generate multiple rules covering different detection angles:
1. HTTP-based detection (web server logs)
2. Application-level detection (application logs)
3. System-level detection (if applicable)
4. File system monitoring (if applicable)

Ensure each rule follows proper Sigma syntax and is actionable for SOC analysts.

Provide your response in the following JSON format:
{format_instructions}
"""
        
        self.prompt = ChatPromptTemplate.from_template(prompt_template)
        self.chain = self.prompt | self.llm | self.parser
    
    def generate_from_analysis(self, analysis: Any) -> SigmaRuleOutput:
        """Generate Sigma rules from an ExploitAnalysis object"""
        
        analysis_data = {
            "vulnerability_type": analysis.vulnerability_type,
            "cve_id": analysis.cve_id,
            "severity": analysis.severity,
            "target_software": analysis.target_software,
            "attack_vector": analysis.attack_vector,
            "impact_description": analysis.impact_description,
            "technical_details": analysis.technical_details,
            "payloads_identified": analysis.payloads_identified,
            "indicators_of_compromise": analysis.indicators_of_compromise,
            "mitigation_recommendations": analysis.mitigation_recommendations,
            "confidence_score": analysis.confidence_score
        }
        
        return self._generate_rules(analysis_data)
    
    def generate_from_json(self, json_file: str) -> List[SigmaRuleOutput]:
        """Generate Sigma rules from JSON analysis results"""
        
        if not os.path.exists(json_file):
            raise FileNotFoundError(f"Analysis file not found: {json_file}")
        
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        results = []
        
        if "analyses" in data:
            # Multiple analyses from directory scan
            for analysis_data in data["analyses"]:
                try:
                    result = self._generate_rules(analysis_data)
                    results.append(result)
                except Exception as e:
                    print(f"Error generating rules for analysis: {e}")
        else:
            # Single analysis
            result = self._generate_rules(data)
            results.append(result)
        
        return results
    
    def generate_from_exploit_file(self, exploit_file: str) -> SigmaRuleOutput:
        """Generate Sigma rules by analyzing an exploit file directly"""
        
        if ExploitAnalyzer is None:
            raise ImportError("ExploitAnalyzer not available. Cannot analyze exploit file directly.")
        
        analyzer = ExploitAnalyzer()
        analysis = analyzer.analyze_file(exploit_file)
        
        return self.generate_from_analysis(analysis)
    
    def _generate_rules(self, analysis_data: Dict[str, Any]) -> SigmaRuleOutput:
        """Generate Sigma rules from analysis data"""
        
        try:
            result = self.chain.invoke({
                "analysis_data": json.dumps(analysis_data, indent=2),
                "format_instructions": self.parser.get_format_instructions()
            })
            
            return SigmaRuleOutput(**result)
            
        except Exception as e:
            raise RuntimeError(f"Sigma rule generation failed: {str(e)}")


def save_sigma_rules(sigma_output: SigmaRuleOutput, output_dir: str, file_prefix: str = "detection"):
    """Save Sigma rules to individual YAML files"""
    
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    saved_files = []
    
    for i, rule_data in enumerate(sigma_output.rules, 1):
        # Create filename from rule title or use index
        rule_title = rule_data.get("title", f"rule_{i}")
        safe_title = "".join(c for c in rule_title if c.isalnum() or c in (' ', '-', '_')).rstrip()
        safe_title = safe_title.replace(' ', '_').lower()
        
        filename = f"{file_prefix}_{safe_title}.yml"
        file_path = output_path / filename
        
        # Write YAML file
        with open(file_path, 'w', encoding='utf-8') as f:
            yaml.dump(rule_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        saved_files.append(str(file_path))
        print(f"✓ Saved Sigma rule: {file_path}")
    
    return saved_files


def print_sigma_summary(sigma_output: SigmaRuleOutput):
    """Print a summary of generated Sigma rules"""
    
    print("\n" + "="*80)
    print("SIGMA DETECTION RULES SUMMARY")
    print("="*80)
    print(f"Rules Generated: {sigma_output.rule_count}")
    print(f"Coverage Areas: {', '.join(sigma_output.coverage_areas)}")
    print(f"Confidence Score: {sigma_output.confidence_score:.2f}")
    
    print(f"\nGenerated Rules:")
    for i, rule in enumerate(sigma_output.rules, 1):
        print(f"  {i}. {rule.get('title', 'Untitled Rule')}")
        print(f"     Level: {rule.get('level', 'Unknown')}")
        print(f"     Log Source: {rule.get('logsource', {}).get('category', 'Unknown')}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Generate Sigma detection rules from exploit analysis")
    parser.add_argument("target", help="Path to exploit file, analysis JSON, or directory")
    parser.add_argument("-o", "--output", help="Output directory for Sigma rules (default: ./result/)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON to stdout")
    parser.add_argument("-m", "--model", default="gpt-4o-mini", help="OpenAI model to use")
    parser.add_argument("-t", "--temperature", type=float, default=0.1, help="Model temperature")
    parser.add_argument("--prefix", default="detection", help="Prefix for output files")
    parser.add_argument("--analyze", action="store_true", 
                        help="Run analysis first (use with exploit files)")
    
    args = parser.parse_args()
    
    # Set default output directory to 'result' folder in script directory
    if not args.output and not args.json:
        script_dir = Path(__file__).parent
        args.output = str(script_dir / "result")
    
    # Check if OpenAI API key is set
    if not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY environment variable is not set")
        sys.exit(1)
    
    # Initialize the generator
    try:
        generator = SigmaRuleGenerator(model_name=args.model, temperature=args.temperature)
    except Exception as e:
        print(f"Error initializing generator: {e}")
        sys.exit(1)
    
    # Determine input type and generate rules
    target_path = Path(args.target)
    all_results = []
    
    try:
        if target_path.is_file():
            if args.target.endswith('.json'):
                # JSON analysis file
                if not args.json:
                    print(f"Generating Sigma rules from analysis: {args.target}")
                results = generator.generate_from_json(args.target)
                all_results.extend(results)
            else:
                # Exploit file - analyze first if requested
                if args.analyze:
                    if not args.json:
                        print(f"Analyzing exploit file and generating Sigma rules: {args.target}")
                    result = generator.generate_from_exploit_file(args.target)
                    all_results.append(result)
                else:
                    print("Error: For exploit files, use --analyze flag to run analysis first")
                    print("Or provide a JSON analysis file instead")
                    sys.exit(1)
        
        elif target_path.is_dir():
            # Directory - look for analysis files
            json_files = list(target_path.glob("*.json"))
            
            if json_files:
                if not args.json:
                    print(f"Generating Sigma rules from analysis files in: {args.target}")
                for json_file in json_files:
                    try:
                        results = generator.generate_from_json(str(json_file))
                        all_results.extend(results)
                        if not args.json:
                            print(f"✓ Processed: {json_file}")
                    except Exception as e:
                        if not args.json:
                            print(f"✗ Failed to process {json_file}: {e}")
            else:
                print("Error: No JSON analysis files found in directory")
                print("Run 3-analyze-exploit.py first to generate analysis files")
                sys.exit(1)
        
        else:
            print(f"Error: Target path does not exist: {args.target}")
            sys.exit(1)
    
    except Exception as e:
        if not args.json:
            print(f"Error during generation: {e}")
        else:
            error_result = {
                "error": str(e),
                "rule_count": 0,
                "generated_at": datetime.now().isoformat(),
                "rules": []
            }
            print(json.dumps(error_result, indent=2, ensure_ascii=False))
        sys.exit(1)
    
    # Output results
    if args.json:
        # Combine all results for JSON output
        combined_rules = []
        total_confidence = 0
        all_coverage = set()
        
        for result in all_results:
            combined_rules.extend(result.rules)
            total_confidence += result.confidence_score
            all_coverage.update(result.coverage_areas)
        
        output_data = {
            "rule_count": len(combined_rules),
            "generated_at": datetime.now().isoformat(),
            "coverage_areas": list(all_coverage),
            "confidence_score": total_confidence / len(all_results) if all_results else 0,
            "rules": combined_rules
        }
        print(json.dumps(output_data, indent=2, ensure_ascii=False))
    
    else:
        # Print summaries and save files
        for i, result in enumerate(all_results):
            print_sigma_summary(result)
            
            # Always save rules (using default or specified output directory)
            prefix = f"{args.prefix}_{i+1}" if len(all_results) > 1 else args.prefix
            save_sigma_rules(result, args.output, prefix)
        
        print(f"\n✓ Sigma rules saved to: {args.output}")
        print("Use --output to specify a different directory")
        print("Example: python 4-craft-detection.py analysis.json --output ./custom_rules/")


if __name__ == "__main__":
    main()