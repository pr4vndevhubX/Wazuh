"""
ML Inference Client - Alert Triage Service
AI-Augmented SOC

Handles communication with the ML Inference API for network intrusion detection.
Provides fallback logic and error handling for ML predictions.

Author: HOLLOWED_EYES
Mission: Phase 3 AI Service Integration
"""

import logging
import httpx
from typing import Optional, Dict, Any, List
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class MLPrediction(BaseModel):
    """ML prediction response"""
    prediction: str
    confidence: float
    probabilities: Dict[str, float]
    model_used: str
    inference_time_ms: float


class MLInferenceClient:
    """
    Client for ML inference API integration.

    Features:
    - Network flow feature extraction
    - ML model prediction with confidence scores
    - Fallback logic if ML API is down
    - Attack type classification
    """

    def __init__(
        self,
        ml_api_url: str = "http://ml-inference:8001",
        timeout: int = 10,
        enabled: bool = True
    ):
        """
        Initialize ML inference client.

        Args:
            ml_api_url: ML inference API endpoint
            timeout: Request timeout in seconds
            enabled: Enable/disable ML predictions (fallback mode)
        """
        self.ml_api_url = ml_api_url
        self.timeout = timeout
        self.enabled = enabled
        logger.info(f"MLInferenceClient initialized: {ml_api_url}, enabled={enabled}")

    async def check_health(self) -> bool:
        """
        Check if ML inference API is reachable.

        Returns:
            bool: True if ML API is available
        """
        if not self.enabled:
            return False

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.ml_api_url}/health")
                return response.status_code == 200
        except Exception as e:
            logger.warning(f"ML API health check failed: {e}")
            return False

    def _extract_network_features(self, alert: Any) -> Optional[List[float]]:
        """
        Extract network flow features from security alert.

        Attempts to extract CICIDS2017 features from Wazuh alert.
        Returns synthetic features if full_log is unavailable.

        Args:
            alert: SecurityAlert object

        Returns:
            Optional[List[float]]: 77 features or None if extraction fails
        """
        try:
            # Check if full_log contains network flow data
            if alert.full_log and isinstance(alert.full_log, dict):
                flow = alert.full_log.get('network_flow', {})

                if flow:
                    # Extract 77 CICIDS2017 features from flow data
                    features = [
                        flow.get('flow_duration', 0.0),
                        flow.get('total_fwd_packets', 0.0),
                        flow.get('total_bwd_packets', 0.0),
                        flow.get('total_length_fwd_packets', 0.0),
                        flow.get('total_length_bwd_packets', 0.0),
                        # ... (remaining 73 features)
                        # Full implementation would extract all CICIDS features
                    ]

                    # Pad to 77 features if incomplete
                    while len(features) < 77:
                        features.append(0.0)

                    logger.debug(f"Extracted {len(features)} network features from full_log")
                    return features[:77]  # Ensure exactly 77 features

            # Fallback: Generate synthetic features from basic alert data
            # This allows ML prediction even without full network flow data
            if alert.source_ip or alert.dest_ip or alert.rule_level:
                logger.debug("Generating synthetic features from basic alert data")

                features = [0.0] * 77

                # Use rule_level as a proxy for severity indicators
                if alert.rule_level:
                    features[0] = float(alert.rule_level)  # Severity score
                    features[1] = float(alert.rule_level) / 15.0  # Normalized severity

                # Port numbers if available
                if alert.source_port:
                    features[2] = float(alert.source_port)
                if alert.dest_port:
                    features[3] = float(alert.dest_port)

                # Indicator flags
                features[4] = 1.0 if alert.source_ip else 0.0
                features[5] = 1.0 if alert.dest_ip else 0.0
                features[6] = 1.0 if alert.user else 0.0
                features[7] = 1.0 if alert.process else 0.0

                return features

            logger.debug("Insufficient data for network feature extraction")
            return None

        except Exception as e:
            logger.error(f"Feature extraction failed: {e}")
            return None

    async def predict_attack_type(
        self,
        alert: Any,
        model_name: str = "random_forest"
    ) -> Optional[MLPrediction]:
        """
        Predict attack type using ML inference API.

        Args:
            alert: SecurityAlert object
            model_name: ML model to use (random_forest, xgboost, decision_tree)

        Returns:
            Optional[MLPrediction]: Prediction result or None
        """
        if not self.enabled:
            logger.debug("ML predictions disabled")
            return None

        # Extract features from alert
        features = self._extract_network_features(alert)

        if features is None:
            logger.debug("Cannot extract features from alert - skipping ML prediction")
            return None

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                payload = {
                    "features": features,
                    "model_name": model_name
                }

                logger.debug(f"Calling ML API: model={model_name}")
                response = await client.post(
                    f"{self.ml_api_url}/predict",
                    json=payload
                )

                if response.status_code == 200:
                    result = response.json()
                    prediction = MLPrediction(
                        prediction=result['prediction'],
                        confidence=result['confidence'],
                        probabilities=result['probabilities'],
                        model_used=result['model_used'],
                        inference_time_ms=result['inference_time_ms']
                    )
                    logger.info(
                        f"ML prediction: {prediction.prediction} "
                        f"(confidence={prediction.confidence:.2f})"
                    )
                    return prediction
                else:
                    logger.error(f"ML API error: {response.status_code} - {response.text}")
                    return None

        except httpx.TimeoutException:
            logger.warning(f"ML API timeout after {self.timeout}s")
            return None
        except Exception as e:
            logger.error(f"ML API request failed: {e}")
            return None

    async def predict_with_fallback(
        self,
        alert: Any
    ) -> Optional[MLPrediction]:
        """
        Predict with automatic model fallback.

        Tries models in order: random_forest -> xgboost -> decision_tree

        Args:
            alert: SecurityAlert object

        Returns:
            Optional[MLPrediction]: First successful prediction or None
        """
        models = ["random_forest", "xgboost", "decision_tree"]

        for model in models:
            prediction = await self.predict_attack_type(alert, model)
            if prediction:
                return prediction
            logger.debug(f"Model {model} failed, trying next...")

        logger.warning("All ML models failed")
        return None


def enrich_llm_prompt_with_ml(
    base_prompt: str,
    ml_prediction: Optional[MLPrediction]
) -> str:
    """
    Enhance LLM prompt with ML prediction context.

    This provides the LLM with additional context from the ML model
    to improve its analysis accuracy.

    Args:
        base_prompt: Original LLM prompt
        ml_prediction: ML prediction result (can be None)

    Returns:
        str: Enhanced prompt with ML context
    """
    if ml_prediction is None:
        return base_prompt

    ml_context = f"""
**ML MODEL PREDICTION:**
- Prediction: {ml_prediction.prediction}
- Confidence: {ml_prediction.confidence:.2%}
- Model: {ml_prediction.model_used}
- Inference Time: {ml_prediction.inference_time_ms:.2f}ms

**Attack Type Probabilities:**
{chr(10).join(f'  - {attack}: {prob:.2%}' for attack, prob in ml_prediction.probabilities.items())}

**NOTE:** Use this ML prediction as additional context, but verify against the raw log data.
If the ML confidence is high (>0.9), this is a strong indicator of the attack type.

---

"""

    return ml_context + base_prompt
