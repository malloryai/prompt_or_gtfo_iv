#!/usr/bin/env python3
"""
MITRE ATT&CK Technique Mapping using LangChain and Structured Outputs

This script maps input strings to relevant MITRE ATT&CK techniques and subtechniques
using LangChain with structured outputs via Pydantic models.

Usage:
    python 6-attack-mapping.py                                               # Run with default test strings
    python 6-attack-mapping.py "your test string here"                       # Run with custom test string
    python 6-attack-mapping.py --model gpt-3.5-turbo "malicious activity"   # Specify different model
    python 6-attack-mapping.py --help                                        # Show detailed help
"""

import argparse
import json
import os
import sys
from typing import List, Optional
from pathlib import Path

from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser

# Disable LangSmith tracing to avoid 403 errors
os.environ["LANGCHAIN_TRACING_V2"] = "false"


class SubtechniqueMatch(BaseModel):
    """Represents a matched MITRE ATT&CK subtechnique."""
    
    subtechnique_id: str = Field(description="The subtechnique ID (e.g., T1037.001)")
    subtechnique_name: str = Field(description="The name of the subtechnique")
    confidence_score: float = Field(description="Confidence score between 0 and 1", ge=0, le=1)


class TechniqueMapping(BaseModel):
    """Represents a mapping of input string to MITRE ATT&CK technique."""
    
    input_string: str = Field(description="The original input string that was analyzed")
    technique_id: str = Field(description="The main technique ID (e.g., T1037)")
    technique_name: str = Field(description="The name of the main technique")
    best_subtechnique: Optional[SubtechniqueMatch] = Field(
        description="The best matching subtechnique, if any"
    )
    alternative_subtechniques: List[SubtechniqueMatch] = Field(
        description="Other relevant subtechniques ranked by confidence",
        default_factory=list
    )
    mapping_rationale: str = Field(
        description="Detailed explanation of why this technique/subtechnique was mapped"
    )
    confidence_score: float = Field(
        description="Overall confidence score for the mapping", ge=0, le=1
    )


class AttackMappingResult(BaseModel):
    """Complete result of MITRE ATT&CK mapping analysis."""
    
    mappings: List[TechniqueMapping] = Field(
        description="List of technique mappings, ranked by relevance"
    )
    analysis_summary: str = Field(
        description="High-level summary of the analysis and key findings"
    )


class MitreAttackMapper:
    """Maps input strings to MITRE ATT&CK techniques using LangChain."""
    
    def __init__(self, attack_data_path: str, model_name: str = "gpt-5"):
        """
        Initialize the mapper with attack data and LLM model.
        
        Args:
            attack_data_path: Path to the enterprise attack subtechniques JSON file
            model_name: OpenAI model name to use
        """
        self.attack_data = self._load_attack_data(attack_data_path)
        self.llm = ChatOpenAI(model=model_name, temperature=0)
        self.parser = PydanticOutputParser(pydantic_object=AttackMappingResult)
        
    def _load_attack_data(self, data_path: str) -> dict:
        """Load and return the MITRE ATT&CK data."""
        with open(data_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _create_attack_context(self) -> str:
        """Create a condensed context string from the attack data for the prompt."""
        context_parts = []
        
        for technique_id, technique_data in self.attack_data.items():
            # Add main technique info
            context_parts.append(
                f"Technique {technique_id} ({technique_data['name']}): "
                f"{technique_data['description'][:200]}..."
            )
            
            # Add subtechniques
            for subtechnique in technique_data.get('subtechniques', []):
                context_parts.append(
                    f"  Subtechnique {subtechnique['technique_id']} ({subtechnique['name']}): "
                    f"{subtechnique['description'][:150]}..."
                )
        
        return "\n".join(context_parts)
    
    def map_string_to_attack(self, input_string: str) -> AttackMappingResult:
        """
        Map an input string to MITRE ATT&CK techniques.
        
        Args:
            input_string: The string to analyze and map
            
        Returns:
            AttackMappingResult containing the mapping analysis
        """
        # Create the prompt template
        prompt_template = ChatPromptTemplate.from_messages([
            ("system", """You are an expert cybersecurity analyst specializing in MITRE ATT&CK framework mapping.
            
Your task is to analyze the provided input string and map it to the most relevant MITRE ATT&CK techniques and subtechniques.

Consider the following when making mappings:
1. Look for keywords that directly relate to attack techniques
2. Consider the context and intent behind the described activity
3. Map to the most specific subtechnique when possible
4. Provide confidence scores based on how well the input matches the technique
5. Explain your reasoning clearly

Available MITRE ATT&CK techniques and subtechniques:
{attack_context}

{format_instructions}"""),
            ("human", "Analyze this input string and map it to relevant MITRE ATT&CK techniques: {input_string}")
        ])
        
        # Create the chain
        chain = prompt_template | self.llm | self.parser
        
        # Execute the mapping
        result = chain.invoke({
            "input_string": input_string,
            "attack_context": self._create_attack_context(),
            "format_instructions": self.parser.get_format_instructions()
        })
        
        return result


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="MITRE ATT&CK Technique Mapping using LangChain and Structured Outputs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s
    Run with default test strings using gpt-5 model
    
  %(prog)s "The attacker used a login script to maintain persistence"
    Map a custom string to MITRE ATT&CK techniques
    
  %(prog)s --model gpt-3.5-turbo "Suspicious network traffic detected"
    Use a different OpenAI model for analysis
    
  %(prog)s --model gpt-5-mini --input "Multiple failed login attempts"
    Specify model and input string explicitly
        """
    )
    
    parser.add_argument(
        "input_string",
        nargs="?",
        help="Input string to analyze and map to MITRE ATT&CK techniques. If not provided, uses default test strings."
    )
    
    parser.add_argument(
        "--model", "-m",
        default="gpt-5",
        help="OpenAI model to use for analysis (default: gpt-5). Examples: gpt-5, gpt-5-mini, gpt-3.5-turbo"
    )
    
    parser.add_argument(
        "--input", "-i",
        dest="input_string_alt",
        help="Alternative way to specify input string (useful when input starts with '-')"
    )
    
    parser.add_argument(
        "--data-path",
        help="Path to enterprise attack subtechniques JSON file (default: ../data/enterprise_attack_subtechniques.json)"
    )
    
    return parser.parse_args()


def main():
    """Main function to demonstrate the MITRE ATT&CK mapping."""
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Determine input string
    input_string = args.input_string or args.input_string_alt
    
    # Path to the attack data
    if args.data_path:
        data_path = Path(args.data_path)
    else:
        data_path = Path(__file__).parent.parent / "data" / "enterprise_attack_subtechniques.json"
    
    # Validate data path exists
    if not data_path.exists():
        print(f"Error: Attack data file not found at {data_path}")
        print("Please ensure the enterprise_attack_subtechniques.json file exists or specify --data-path")
        sys.exit(1)
    
    # Initialize the mapper with specified model
    print(f"Initializing MITRE ATT&CK mapper with model: {args.model}")
    try:
        mapper = MitreAttackMapper(str(data_path), model_name=args.model)
    except Exception as e:
        print(f"Error initializing mapper: {e}")
        print("Please check that your OpenAI API key is set and the model name is valid.")
        sys.exit(1)
    
    # Determine test strings
    if input_string:
        test_strings = [input_string]
    else:
        # Use default test strings
        test_strings = [
            "The attacker used a login script to maintain persistence on the Windows system",
            "Suspicious network traffic indicates potential man-in-the-middle attack",
            "Malicious RC script found in /etc/rc.local for persistence",
            "Evil twin WiFi access point detected capturing credentials"
        ]
    
    print("MITRE ATT&CK Technique Mapping Results")
    print("=" * 50)
    
    for test_string in test_strings:
        print(f"\nInput: {test_string}")
        print("-" * 30)
        
        try:
            result = mapper.map_string_to_attack(test_string)
            
            print(f"Analysis Summary: {result.analysis_summary}")
            print(f"Number of mappings found: {len(result.mappings)}")
            
            for i, mapping in enumerate(result.mappings, 1):
                print(f"\nMapping {i}:")
                print(f"  Technique: {mapping.technique_id} - {mapping.technique_name}")
                print(f"  Confidence: {mapping.confidence_score:.2f}")
                
                if mapping.best_subtechnique:
                    st = mapping.best_subtechnique
                    print(f"  Best Subtechnique: {st.subtechnique_id} - {st.subtechnique_name}")
                    print(f"  Subtechnique Confidence: {st.confidence_score:.2f}")
                
                print(f"  Rationale: {mapping.mapping_rationale}")
                
                if mapping.alternative_subtechniques:
                    print(f"  Alternatives: {len(mapping.alternative_subtechniques)} other subtechniques")
                    
        except Exception as e:
            print(f"Error processing '{test_string}': {e}")
        
        print("\n" + "="*50)


if __name__ == "__main__":
    main()
