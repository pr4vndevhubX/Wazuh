"""
LLM Client - Alert Triage Service (AI-Augmented SOC)

Supports:
- Ollama (local LLM)
- Groq (cloud LLM)

Includes:
- Prompt engineering for SOC alert triage
- Optional ML enrichment
- Provider-based routing (Ollama / Groq)
- Structured JSON parsing with validation
"""

import json
import logging
from typing import Optional

import httpx
from groq import Groq

from config import settings
from models import (
    SecurityAlert,
    TriageResponse,
    SeverityLevel,
    AlertCategory,
    IOC,
    TriageRecommendation,
)
from ml_client import MLInferenceClient, enrich_llm_prompt_with_ml

logger = logging.getLogger(__name__)

# -------------------------------
# Category normalization
# -------------------------------
CATEGORY_ALIASES = {
    "exfiltration": "data_exfiltration",
    "data_theft": "data_exfiltration",
    "privilege_elevation": "privilege_escalation",
    "privesc": "privilege_escalation",
    "lateral": "lateral_movement",
    "c2": "command_and_control",
    "c&c": "command_and_control",
    "recon": "reconnaissance",
    "scanning": "reconnaissance",
    "intrusion": "intrusion_attempt",
    "attack": "intrusion_attempt",
    "policy": "policy_violation",
    "compliance": "policy_violation",
}


def normalize_category(category: str) -> str:
    category = category.lower().strip()
    if category in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[category]

    valid = [c.value for c in AlertCategory]
    if category in valid:
        return category

    logger.warning(f"Unknown category '{category}', defaulting to 'other'")
    return "other"


# =====================================================
# LLM CLIENT
# =====================================================
class OllamaClient:
    """
    Unified LLM client for SOC alert triage.
    Routes requests to:
    - Ollama (local)
    - Groq (cloud)
    """

    def __init__(self):
        self.provider = settings.llm_provider  # "ollama" or "groq"
        self.timeout = settings.llm_timeout

        # ML client
        self.ml_client = MLInferenceClient(
            ml_api_url=settings.ml_api_url,
            timeout=settings.ml_timeout,
            enabled=settings.ml_enabled,
        )

        if self.provider == "groq":
            logger.info("Initializing Groq LLM provider")
            self.groq_client = Groq(api_key=settings.groq_api_key)
            self.model = settings.groq_model
        else:
            logger.info("Initializing Ollama LLM provider")
            self.base_url = settings.ollama_host
            self.primary_model = settings.primary_model
            self.fallback_model = settings.fallback_model
            self.model = self.primary_model

    # -------------------------------------------------
    # Health checks
    # -------------------------------------------------
    async def check_health(self) -> bool:
        """
        Check if LLM provider is reachable.

        Returns:
            bool: True if provider is available
        """
        if self.provider == "groq":
            return await self._check_groq_health()
        else:
            return await self._check_ollama_health()

    async def _check_groq_health(self) -> bool:
        """Check Groq API health"""
        try:
            # Simple API test with minimal token usage
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=5,
                temperature=0.0
            )
            logger.info("Groq API health check: OK")
            return True
        except Exception as e:
            logger.error(f"Groq health check failed: {e}")
            return False

    async def _check_ollama_health(self) -> bool:
        """Check Ollama service health"""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/api/tags")
                if response.status_code == 200:
                    logger.info("Ollama service health check: OK")
                    return True
                else:
                    logger.warning(f"Ollama health check returned {response.status_code}")
                    return False
        except Exception as e:
            logger.error(f"Ollama health check failed: {e}")
            return False

    # -------------------------------------------------
    # Prompt builder
    # -------------------------------------------------
    def _build_triage_prompt(self, alert: SecurityAlert) -> str:
        return f"""
You are an expert cybersecurity analyst performing alert triage for a SOC.

TASK:
Analyze the alert and respond ONLY in valid JSON.

ALERT DETAILS:
- Alert ID: {alert.alert_id}
- Rule: {alert.rule_description} (Level {alert.rule_level})
- Timestamp: {alert.timestamp}
- Source IP: {alert.source_ip or "N/A"}
- Destination IP: {alert.dest_ip or "N/A"}
- User: {alert.user or "N/A"}
- Process: {alert.process or "N/A"}
- Raw Log: {alert.raw_log or "N/A"}

RULES:
- Do NOT hallucinate
- If data is insufficient, state "INSUFFICIENT_DATA"
- Extract only real IOCs
- Provide confidence score (0.0-1.0)

OUTPUT JSON FORMAT:
{{
  "severity": "high",
  "category": "intrusion_attempt",
  "confidence": 0.9,
  "summary": "Short summary",
  "detailed_analysis": "Evidence-based analysis",
  "potential_impact": "Impact description",
  "is_true_positive": true,
  "false_positive_reason": null,
  "iocs": [
    {{"ioc_type": "ip", "value": "1.2.3.4", "confidence": 0.95}}
  ],
  "mitre_techniques": ["T1110"],
  "mitre_tactics": ["TA0006"],
  "recommendations": [
    {{"action": "Block IP", "priority": 1, "rationale": "Stops attack"}}
  ],
  "investigation_priority": 2,
  "estimated_analyst_time": 15
}}
"""

    # -------------------------------------------------
    # Provider router
    # -------------------------------------------------
    async def _call_llm(self, prompt: str) -> Optional[str]:
        if self.provider == "groq":
            return await self._call_groq(prompt)
        return await self._call_ollama(prompt, self.primary_model)

    # -------------------------------------------------
    # Groq API
    # -------------------------------------------------
    async def _call_groq(self, prompt: str) -> Optional[str]:
        try:
            logger.info(f"Calling Groq API with model: {self.model}")
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=settings.llm_temperature,
                max_tokens=settings.max_tokens,
                response_format={"type": "json_object"},
            )
            logger.info("Groq API call successful")
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return None

    # -------------------------------------------------
    # Ollama API
    # -------------------------------------------------
    async def _call_ollama(
        self, prompt: str, model: str, temperature: float = 0.1
    ) -> Optional[str]:
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "model": model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": temperature,
                        "num_predict": settings.max_tokens,
                    },
                    "format": "json",
                }
                logger.info(f"Calling Ollama model: {model}")
                response = await client.post(
                    f"{self.base_url}/api/generate", json=payload
                )

                if response.status_code == 200:
                    logger.info("Ollama API call successful")
                    return response.json().get("response")

                logger.error(f"Ollama error {response.status_code}: {response.text}")
                return None
        except httpx.TimeoutException:
            logger.error(f"Ollama timeout after {self.timeout}s")
            return None
        except Exception as e:
            logger.error(f"Ollama call failed: {e}")
            return None

    # -------------------------------------------------
    # Parse LLM response
    # -------------------------------------------------
    def _parse_llm_response(
        self, alert: SecurityAlert, llm_output: str, model_used: str
    ) -> Optional[TriageResponse]:
        try:
            text = llm_output.strip()

            # Remove markdown code blocks
            if text.startswith("```"):
                text = "\n".join(text.splitlines()[1:-1])

            parsed = json.loads(text)

            return TriageResponse(
                alert_id=alert.alert_id,
                severity=SeverityLevel(parsed.get("severity", "medium")),
                category=AlertCategory(
                    normalize_category(parsed.get("category", "other"))
                ),
                confidence=float(parsed.get("confidence", 0.5)),
                summary=parsed.get("summary", ""),
                detailed_analysis=parsed.get("detailed_analysis", ""),
                potential_impact=parsed.get("potential_impact", ""),
                is_true_positive=parsed.get("is_true_positive", True),
                false_positive_reason=parsed.get("false_positive_reason"),
                iocs=[IOC(**ioc) for ioc in parsed.get("iocs", [])],
                mitre_techniques=parsed.get("mitre_techniques", []),
                mitre_tactics=parsed.get("mitre_tactics", []),
                recommendations=[
                    TriageRecommendation(**r)
                    for r in parsed.get("recommendations", [])
                ],
                investigation_priority=int(parsed.get("investigation_priority", 3)),
                estimated_analyst_time=parsed.get("estimated_analyst_time"),
                model_used=model_used,
            )

        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            logger.debug(f"Raw output: {llm_output[:500]}")
            return None
        except Exception as e:
            logger.error(f"LLM response parse error: {e}")
            return None

    # -------------------------------------------------
    # Main entrypoint
    # -------------------------------------------------
    async def analyze_alert(self, alert: SecurityAlert) -> Optional[TriageResponse]:
        """
        Main entrypoint: Analyze security alert using LLM with ML enhancement.

        Workflow:
        1. Attempt ML prediction for additional context
        2. Enhance LLM prompt with ML results
        3. Call LLM (Groq or Ollama based on provider)
        4. Parse and return structured response

        Args:
            alert: SecurityAlert to analyze

        Returns:
            Optional[TriageResponse]: Analysis result or None
        """
        # Step 1: Get ML prediction (if available)
        ml_prediction = None
        if settings.ml_enabled:
            logger.debug("Attempting ML prediction...")
            ml_prediction = await self.ml_client.predict_with_fallback(alert)
            if ml_prediction:
                logger.info(
                    f"ML prediction: {ml_prediction.prediction} "
                    f"(confidence={ml_prediction.confidence:.2f})"
                )

        # Step 2: Build prompt with ML enrichment
        base_prompt = self._build_triage_prompt(alert)
        enriched_prompt = enrich_llm_prompt_with_ml(base_prompt, ml_prediction)

        # Step 3: Call LLM
        logger.info(f"Analyzing alert {alert.alert_id} with {self.provider}")
        llm_output = await self._call_llm(enriched_prompt)

        if not llm_output:
            logger.error(f"LLM call failed for alert {alert.alert_id}")
            return None

        # Step 4: Parse response
        response = self._parse_llm_response(alert, llm_output, self.model)
        
        if response:
            # Add ML metadata to response
            if ml_prediction:
                response.ml_prediction = ml_prediction.prediction
                response.ml_confidence = ml_prediction.confidence
            logger.info(
                f"Alert {alert.alert_id} analyzed: "
                f"severity={response.severity}, confidence={response.confidence:.2f}"
            )
            return response
        else:
            logger.error(f"Failed to parse LLM response for alert {alert.alert_id}")
            return None


# TODO: Week 5 - Add RAG integration
# class RAGEnhancedClient(OllamaClient):
#     """Extended client with RAG capabilities"""
#     async def get_rag_context(self, alert: SecurityAlert) -> str:
#         """Query RAG service for relevant context"""
#         pass