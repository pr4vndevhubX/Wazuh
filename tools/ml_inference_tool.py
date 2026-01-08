from crewai.tools import BaseTool
import requests

class MLInferenceTool(BaseTool):
    name: str = "ML Network Traffic Classifier"
    description: str = "Classifies network traffic as BENIGN or ATTACK using ML models. Requires 77 network flow features."
    
    def _run(self, features: list) -> str:
        response = requests.post(
            "http://localhost:8500/predict",
            json={"features": features, "model_name": "random_forest"}
        )
        return response.json()