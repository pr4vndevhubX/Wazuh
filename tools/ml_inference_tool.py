"""
ML Inference Tool
Connects crew to ML traffic classification service
"""

from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import requests
import logging

logger = logging.getLogger(__name__)


class MLInferenceInput(BaseModel):
    """Input for ML Inference"""
    ip_address: str = Field(..., description="IP address to analyze")
    features: list = Field(default=None, description="Network flow features (77 dimensions)")


class MLInferenceTool(BaseTool):
    name: str = "ML Traffic Classifier"
    description: str = (
        "Classifies network traffic using trained ML models (RandomForest/XGBoost). "
        "Predicts if traffic is BENIGN or ATTACK with confidence score."
    )
    args_schema: Type[BaseModel] = MLInferenceInput
    
    def _run(self, ip_address: str, features: list = None) -> dict:
        """
        Run ML classification on IP traffic.
        
        Args:
            ip_address: IP to analyze
            features: Optional flow features (if None, uses zero vector)
            
        Returns:
            dict: ML prediction results
        """
        try:
            # Use zero features if not provided (placeholder)
            if features is None:
                features = [0.0] * 77  # CICIDS2017 feature count
            
            response = requests.post(
                "http://localhost:8500/predict",
                json={
                    "features": features,
                    "model_name": "random_forest"
                },
                timeout=15
            )
            
            if not response.ok:
                logger.warning(f"ML service error: {response.status_code}")
                return {
                    "prediction": "UNKNOWN",
                    "confidence": 0.0,
                    "error": f"Service unavailable: {response.status_code}",
                    "model_used": "none"
                }
            
            data = response.json()
            
            result = {
                "prediction": data.get("prediction", "UNKNOWN"),
                "confidence": data.get("confidence", 0.0),
                "model_used": data.get("model_used", "random_forest"),
                "probabilities": data.get("probabilities", {}),
                "inference_time_ms": data.get("inference_time_ms", 0),
                "ip_analyzed": ip_address
            }
            
            logger.info(f"ML prediction for {ip_address}: {result['prediction']} ({result['confidence']:.2f})")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"ML service connection error: {e}")
            return {
                "prediction": "SERVICE_UNAVAILABLE",
                "confidence": 0.0,
                "error": f"Cannot connect to ML service: {str(e)}",
                "model_used": "none",
                "ip_analyzed": ip_address
            }
        except Exception as e:
            logger.error(f"ML inference error: {e}")
            return {
                "prediction": "ERROR",
                "confidence": 0.0,
                "error": str(e),
                "ip_analyzed": ip_address
            }