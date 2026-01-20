"""
RAG MITRE Context Tool
Retrieves MITRE ATT&CK context from RAG service
"""

from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import requests
import logging

logger = logging.getLogger(__name__)


class RAGMitreInput(BaseModel):
    """Input for RAG MITRE retrieval"""
    query: str = Field(..., description="Search query for MITRE ATT&CK")
    top_k: int = Field(default=5, description="Number of results to return")


class RAGMitreTool(BaseTool):
    name: str = "MITRE ATT&CK Context Retriever"
    description: str = (
        "Retrieves relevant MITRE ATT&CK tactics, techniques, and procedures "
        "from the RAG knowledge base using semantic search."
    )
    args_schema: Type[BaseModel] = RAGMitreInput
    
    def _run(self, query: str, top_k: int = 5) -> dict:
        """
        Retrieve MITRE context from RAG service.
        
        Args:
            query: Search query (e.g., "SSH brute force", "lateral movement")
            top_k: Number of techniques to return
            
        Returns:
            dict: MITRE techniques and context
        """
        try:
            response = requests.post(
                "http://localhost:8001/retrieve",
                json={
                    "query": query,
                    "collection": "mitre_attack",
                    "top_k": top_k,
                    "min_similarity": 0.3
                },
                timeout=15
            )
            
            if not response.ok:
                logger.warning(f"RAG service error: {response.status_code}")
                return {
                    "techniques_found": 0,
                    "techniques": [],
                    "error": f"Service unavailable: {response.status_code}"
                }
            
            data = response.json()
            
            # Extract techniques
            techniques = []
            for result in data.get("results", []):
                technique = {
                    "technique_id": result.get("metadata", {}).get("technique_id", "N/A"),
                    "name": result.get("metadata", {}).get("name", "Unknown"),
                    "tactic": result.get("metadata", {}).get("tactic", "N/A"),
                    "description": result.get("document", "")[:300] + "...",
                    "similarity_score": result.get("similarity_score", 0.0),
                    "platforms": result.get("metadata", {}).get("platforms", [])
                }
                techniques.append(technique)
            
            result = {
                "techniques_found": len(techniques),
                "techniques": techniques,
                "query_used": query,
                "collection": "mitre_attack",
                "service_status": "available"
            }
            
            logger.info(f"RAG MITRE query '{query}': {len(techniques)} techniques found")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"RAG service connection error: {e}")
            return {
                "techniques_found": 0,
                "techniques": [],
                "error": f"Cannot connect to RAG service: {str(e)}",
                "service_status": "unavailable"
            }
        except Exception as e:
            logger.error(f"RAG query error: {e}")
            return {
                "techniques_found": 0,
                "techniques": [],
                "error": str(e)
            }