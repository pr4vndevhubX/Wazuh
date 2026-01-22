"""
Configuration Management - Alert Triage Service
AI-Augmented SOC

Manages environment variables and service configuration with Pydantic.
"""

from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Environment variables should be prefixed with TRIAGE_
    Example: TRIAGE_OLLAMA_HOST=http://ollama:11434
    """

    # --------------------------------------------------
    # Service Configuration
    # --------------------------------------------------
    service_name: str = "alert-triage"
    service_version: str = "1.0.0"
    log_level: str = "INFO"

    # --------------------------------------------------
    # LLM Provider Selection
    # --------------------------------------------------
    llm_provider: str = "groq"  # groq | ollama

    # --------------------------------------------------
    # Groq LLM Configuration
    # --------------------------------------------------
    groq_api_key: str = ""
    groq_api_base: str = "https://api.groq.com/openai/v1"
    groq_model: str = "llama-3.3-70b-versatile"

    # --------------------------------------------------
    # Ollama LLM Configuration (Fallback / Local)
    # --------------------------------------------------
    ollama_host: str = "http://ollama:11434"
    primary_model: str = "llama3.1:8b"
    fallback_model: str = "llama3.2:3b"

    # --------------------------------------------------
    # LLM Parameters
    # --------------------------------------------------
    llm_temperature: float = 0.1
    llm_timeout: int = 60
    max_tokens: int = 2048

    # --------------------------------------------------
    # Confidence Thresholds
    # --------------------------------------------------
    high_confidence_threshold: float = 0.85
    medium_confidence_threshold: float = 0.70
    auto_action_threshold: float = 0.80

    # --------------------------------------------------
    # ML Inference Configuration
    # --------------------------------------------------
    ml_enabled: bool = True
    ml_api_url: str = "http://ids-inference:8500"
    ml_timeout: int = 10
    ml_default_model: str = "random_forest"

    # --------------------------------------------------
    # RAG Configuration (Phase 3.2)
    # --------------------------------------------------
    rag_enabled: bool = False
    rag_service_url: Optional[str] = "http://rag-service:8001"
    rag_top_k: int = 3

    # --------------------------------------------------
    # Wazuh Integration
    # --------------------------------------------------
    wazuh_dashboard_url: Optional[str] = None
    wazuh_api_url: Optional[str] = None

    # --------------------------------------------------
    # TheHive Integration
    # --------------------------------------------------
    thehive_url: Optional[str] = None
    thehive_api_key: Optional[str] = None

    # --------------------------------------------------
    # Performance Tuning
    # --------------------------------------------------
    max_concurrent_requests: int = 10
    request_timeout: int = 120

    # --------------------------------------------------
    # API Security
    # --------------------------------------------------
    api_key_enabled: bool = False
    api_key: Optional[str] = None

    # --------------------------------------------------
    # Pydantic v2 Configuration
    # --------------------------------------------------
    model_config = SettingsConfigDict(
        env_prefix="TRIAGE_",
        env_file=".env",
        case_sensitive=False,
        extra="ignore"  # 🔥 CRITICAL FIX (prevents crashes)
    )


# Global settings instance
settings = Settings()
