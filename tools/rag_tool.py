"""
RAG Tool - MITRE ATT&CK Knowledge Retriever
Queries the RAG service for threat intelligence context
"""

from crewai.tools import BaseTool
import requests
from typing import Any


class RAGTool(BaseTool):
    name: str = "MITRE ATT&CK Knowledge Retriever"
    description: str = (
        "Retrieves MITRE ATT&CK tactics, techniques, and threat context. "
        "Use this to enrich threat analysis with standardized attack patterns. "
        "Query with threat-related keywords (e.g., 'SSH brute force', 'ransomware C2', 'credential dumping')."
    )
    
    def _run(self, query: str) -> str:
        """
        Query the RAG service for MITRE ATT&CK context.
        
        Args:
            query: Search query (e.g., "SSH brute force", "lateral movement")
            
        Returns:
            Structured MITRE ATT&CK context or error message
        """
        try:
            # Call RAG service
            response = requests.post(
                "http://localhost:8001/retrieve",
                json={
                    "query": query,
                    "collection": "mitre_attack",
                    "top_k": 5,
                    "min_similarity": 0.3
                },
                timeout=30
            )
            
            # Handle service unavailability
            if not response.ok:
                return "⚠️ MITRE ATT&CK service unavailable - continuing without MITRE context."
            
            data = response.json()
            
            # Handle no results
            if not data.get("results") or data.get("total_results", 0) == 0:
                return f"ℹ️ No relevant MITRE ATT&CK techniques found for query: '{query}'"
            
            # Build structured output
            output = ["📊 MITRE ATT&CK CONTEXT:", ""]
            output.append(f"Query: {query}")
            output.append(f"Found: {data.get('total_results', 0)} relevant techniques")
            output.append("")
            
            for idx, result in enumerate(data["results"], 1):
                metadata = result.get("metadata", {})
                
                # Extract technique details
                name = metadata.get("name", "Unknown Technique")
                tactics = metadata.get("tactics", "[]")
                platforms = metadata.get("platforms", "[]")
                score = result.get("similarity_score", 0.0)
                
                # Clean up tactics formatting
                tactics_str = tactics.strip("[]").replace('"', '').replace("'", "")
                
                # Format output
                output.append(f"{idx}. {name}")
                output.append(f"   Tactics: {tactics_str}")
                output.append(f"   Platforms: {platforms}")
                output.append(f"   Relevance Score: {score:.2f}")
                output.append("")
            
            output.append("⚠️ CRITICAL: Use ONLY the techniques listed above.")
            output.append("⚠️ DO NOT invent or assume any MITRE techniques not shown here.")
            
            return "\n".join(output)
            
        except requests.exceptions.Timeout:
            return "⚠️ MITRE ATT&CK service timeout - continuing without MITRE context."
        
        except requests.exceptions.ConnectionError:
            return "⚠️ MITRE ATT&CK service not reachable - continuing without MITRE context."
        
        except Exception as e:
            return f"⚠️ MITRE ATT&CK service error: {str(e)} - continuing without MITRE context."