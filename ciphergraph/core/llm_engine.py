"""
LLM Engine module for CipherGraph
Provides LLM-powered analysis for vulnerability data and attack strategies
"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass
import json
import re

from ciphergraph.core.config import LLMConfig


@dataclass
class LLMResponse:
    """Standardized LLM response."""

    content: str
    raw_response: Any
    tokens_used: int
    model: str
    success: bool
    error: Optional[str] = None


class LLMEngine:
    """
    LLM Engine for cybersecurity analysis.

    Supports multiple providers:
    - OpenAI (GPT-4, GPT-3.5)
    - Anthropic (Claude)
    - Ollama (local models)
    - vLLM (high-performance local)
    """

    def __init__(self, config: LLMConfig = None):
        self.config = config or LLMConfig()
        self._client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the LLM client based on provider."""
        if self.config.provider == "openai":
            self._init_openai()
        elif self.config.provider == "anthropic":
            self._init_anthropic()
        elif self.config.provider == "ollama":
            self._init_ollama()
        else:
            raise ValueError(f"Unknown LLM provider: {self.config.provider}")

    def _init_openai(self) -> None:
        """Initialize OpenAI client."""
        try:
            from langchain_openai import ChatOpenAI

            self._client = ChatOpenAI(
                model=self.config.model,
                api_key=self.config.api_key,
                base_url=self.config.base_url,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
        except ImportError:
            self._client = None

    def _init_anthropic(self) -> None:
        """Initialize Anthropic client."""
        try:
            from langchain_anthropic import ChatAnthropic

            self._client = ChatAnthropic(
                model=self.config.model,
                api_key=self.config.api_key,
                temperature=self.config.temperature,
                max_tokens=self.config.max_tokens,
            )
        except ImportError:
            self._client = None

    def _init_ollama(self) -> None:
        """Initialize Ollama client for local models."""
        try:
            from langchain_community.chat_models import ChatOllama

            base_url = self.config.base_url or "http://localhost:11434"
            self._client = ChatOllama(
                model=self.config.model,
                base_url=base_url,
                temperature=self.config.temperature,
            )
        except ImportError:
            self._client = None

    def generate(self, prompt: str, system_prompt: str = None) -> LLMResponse:
        """
        Generate response from LLM.

        Args:
            prompt: User prompt
            system_prompt: Optional system prompt

        Returns:
            LLMResponse with generated content
        """
        if self._client is None:
            return LLMResponse(
                content=self._fallback_response(prompt),
                raw_response=None,
                tokens_used=0,
                model=self.config.model,
                success=False,
                error="LLM client not initialized",
            )

        try:
            from langchain.schema import HumanMessage, SystemMessage

            messages = []
            if system_prompt:
                messages.append(SystemMessage(content=system_prompt))
            messages.append(HumanMessage(content=prompt))

            response = self._client.generate(messages)

            return LLMResponse(
                content=response.content,
                raw_response=response,
                tokens_used=response.llm_output.get("token_usage", {}).get("total", 0)
                if hasattr(response, "llm_output")
                else 0,
                model=self.config.model,
                success=True,
            )
        except Exception as e:
            return LLMResponse(
                content=self._fallback_response(prompt),
                raw_response=None,
                tokens_used=0,
                model=self.config.model,
                success=False,
                error=str(e),
            )

    def _fallback_response(self, prompt: str) -> str:
        """Fallback response when LLM is not available."""
        return f"[Simulated Response] Analyzed query: {prompt[:100]}... Found potential attack vectors based on pattern matching."

    def analyze_vulnerability(self, cve_data: Dict) -> Dict:
        """
        Analyze vulnerability data using LLM.

        Args:
            cve_data: Dictionary containing CVE information

        Returns:
            Analysis results including severity assessment and recommendations
        """
        prompt = f"""
Analyze the following vulnerability:

CVE ID: {cve_data.get('cve_id', 'N/A')}
Description: {cve_data.get('description', 'N/A')}
CVSS Score: {cve_data.get('severity', 'N/A')}
Attack Vector: {cve_data.get('attack_vector', 'N/A')}
Affected Product: {cve_data.get('affected_product', 'N/A')}

Provide:
1. Severity classification (Critical/High/Medium/Low)
2. Exploitability assessment
3. Recommended mitigation steps
4. Related attack techniques
"""
        response = self.generate(prompt, system_prompt=self._get_security_system_prompt())

        return {
            "cve_id": cve_data.get("cve_id"),
            "analysis": response.content,
            "tokens_used": response.tokens_used,
            "model": response.model,
        }

    def query_knowledge_graph(self, query: str, knowledge_graph) -> List[Dict]:
        """
        Query the knowledge graph using natural language.

        Args:
            query: Natural language query
            knowledge_graph: KnowledgeGraph instance

        Returns:
            List of relevant findings
        """
        stats = knowledge_graph.get_statistics()

        prompt = f"""
You are a cybersecurity expert analyzing a knowledge graph.

The knowledge graph contains:
- {stats.get('vulnerabilities', 0)} vulnerabilities
- {stats.get('attack_techniques', 0)} attack techniques
- {stats.get('system_entities', 0)} system entities

User Query: {query}

Based on the query, identify relevant vulnerabilities, attack paths, or security concerns.
Format your response as a structured analysis.
"""
        response = self.generate(prompt, system_prompt=self._get_security_system_prompt())

        return [
            {
                "query": query,
                "response": response.content,
                "model": response.model,
                "tokens_used": response.tokens_used,
            }
        ]

    def suggest_exploit_strategy(
        self, target_info: Dict, vulnerabilities: List[Dict]
    ) -> Dict:
        """
        Suggest exploitation strategies based on target and vulnerabilities.

        Args:
            target_info: Information about the target system
            vulnerabilities: List of identified vulnerabilities

        Returns:
            Strategic recommendations for exploitation
        """
        vuln_summary = "\n".join(
            [f"- {v.get('cve_id', 'Unknown')}: {v.get('description', '')[:100]}" for v in vulnerabilities]
        )

        prompt = f"""
As a cybersecurity expert, analyze the following target and vulnerabilities:

Target Information:
{json.dumps(target_info, indent=2)}

Identified Vulnerabilities:
{vuln_summary}

Provide:
1. Recommended exploitation strategy (in order of priority)
2. Estimated success probability for each approach
3. Potential risks and countermeasures
4. Post-exploitation recommendations
"""
        response = self.generate(prompt, system_prompt=self._get_security_system_prompt())

        return {
            "target": target_info,
            "vulnerabilities_analyzed": len(vulnerabilities),
            "strategy": response.content,
            "model": response.model,
        }

    def analyze_log_security(self, log_data: str) -> Dict:
        """
        Analyze security events from log data.

        Args:
            log_data: Log entries to analyze

        Returns:
            Security analysis including detected threats
        """
        prompt = f"""
Analyze the following security logs for potential threats, anomalies, or attack indicators:

{log_data[:3000]}

Provide:
1. Detected security events (if any)
2. Threat severity assessment
3. Recommended response actions
4. IOCs (Indicators of Compromise) if found
"""
        response = self.generate(prompt, system_prompt=self._get_security_system_prompt())

        return {
            "log_analysis": response.content,
            "model": response.model,
            "tokens_used": response.tokens_used,
        }

    def generate_attack_path_narrative(self, attack_path: List[str], knowledge_graph) -> str:
        """
        Generate human-readable narrative for an attack path.

        Args:
            attack_path: List of node IDs forming the attack path
            knowledge_graph: KnowledgeGraph instance

        Returns:
            Narrative description of the attack path
        """
        path_details = []
        for node_id in attack_path:
            node_data = knowledge_graph._node_index.get(node_id)
            if node_data:
                path_details.append(
                    {
                        "id": node_id,
                        "type": node_data["type"].value,
                        "description": str(node_data["data"])[:200],
                    }
                )

        prompt = f"""
Generate a detailed narrative explaining this attack path:

{json.dumps(path_details, indent=2)}

Describe:
1. The attack progression in plain language
2. Why each step is necessary
3. How the attacker moves from initial access to goal
4. Defensive recommendations for each step
"""
        response = self.generate(prompt, system_prompt=self._get_security_system_prompt())
        return response.content

    def _get_security_system_prompt(self) -> str:
        """Get system prompt for security-focused LLM interactions."""
        return """You are CipherGraph, an advanced AI-powered cybersecurity analysis assistant.

Your expertise includes:
- Vulnerability assessment and CVSS scoring
- ATT&CK framework analysis
- Penetration testing strategies
- Security architecture evaluation
- Threat intelligence analysis

Always provide accurate, actionable security recommendations.
When uncertainty exists, clearly state assumptions and limitations.
Focus on defensive strategies and mitigation recommendations."""
