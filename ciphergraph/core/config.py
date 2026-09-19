"""
Configuration management for CipherGraph
"""

import os
from typing import Optional
from pydantic import BaseModel, Field
from pathlib import Path


class GraphConfig(BaseModel):
    """Configuration for knowledge graph."""

    backend: str = Field(default="networkx", description="Graph backend: networkx or neo4j")
    neo4j_uri: Optional[str] = Field(default=None, description="Neo4j connection URI")
    neo4j_user: Optional[str] = Field(default=None, description="Neo4j username")
    neo4j_password: Optional[str] = Field(default=None, description="Neo4j password")


class LLMConfig(BaseModel):
    """Configuration for LLM engine."""

    provider: str = Field(default="openai", description="LLM provider: openai, anthropic, or ollama")
    model: str = Field(default="gpt-4", description="Model name")
    api_key: Optional[str] = Field(default=None, description="API key")
    base_url: Optional[str] = Field(default=None, description="Custom base URL for API")
    temperature: float = Field(default=0.7, description="Sampling temperature")
    max_tokens: int = Field(default=2000, description="Maximum tokens to generate")


class Config(BaseModel):
    """Main configuration for CipherGraph."""

    graph_config: GraphConfig = Field(default_factory=GraphConfig)
    llm_config: LLMConfig = Field(default_factory=LLMConfig)
    log_level: str = Field(default="INFO", description="Logging level")

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        return cls(
            graph_config=GraphConfig(
                backend=os.getenv("CIPHERGRAPH_GRAPH_BACKEND", "networkx"),
                neo4j_uri=os.getenv("NEO4J_URI"),
                neo4j_user=os.getenv("NEO4J_USER"),
                neo4j_password=os.getenv("NEO4J_PASSWORD"),
            ),
            llm_config=LLMConfig(
                provider=os.getenv("CIPHERGRAPH_LLM_PROVIDER", "openai"),
                model=os.getenv("CIPHERGRAPH_LLM_MODEL", "gpt-4"),
                api_key=os.getenv("OPENAI_API_KEY"),
                base_url=os.getenv("LLM_BASE_URL"),
                temperature=float(os.getenv("LLM_TEMPERATURE", "0.7")),
                max_tokens=int(os.getenv("LLM_MAX_TOKENS", "2000")),
            ),
            log_level=os.getenv("CIPHERGRAPH_LOG_LEVEL", "INFO"),
        )

    @classmethod
    def from_file(cls, config_path: str) -> "Config":
        """Load configuration from YAML file."""
        import yaml

        path = Path(config_path)
        if path.exists():
            with open(path) as f:
                data = yaml.safe_load(f)
            return cls(**data)
        return cls()
