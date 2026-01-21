#!/usr/bin/env python3
"""
Test CrewAI Investigation Endpoint
Tests the analyst-triggered deep investigation
"""

import requests
import json
import time


INTEGRATION_URL = "http://localhost:8002"


def test_crewai_investigation(alert_id: str = "test-alert-001", ip_address: str = "8.8.8.8"):
    """
    Test the /investigate/{alert_id} endpoint
    This simulates an analyst clicking 'Investigate' in the dashboard
    """
    
    print("🔍 Testing CrewAI Investigation Endpoint")
    print("=" * 60)
    print(f"Alert ID: {alert_id}")
    print(f"IP Address: {ip_address}")
    print("=" * 60)
    
    try:
        print("\n⏳ Starting CrewAI investigation (this may take 30-60 seconds)...")
        
        start_time = time.time()
        
        response = requests.post(
            f"{INTEGRATION_URL}/investigate/{alert_id}",
            timeout=300  # 5 minutes max
        )
        
        duration = time.time() - start_time
        
        print(f"\n📡 Response received in {duration:.2f}s")
        print(f"Status Code: {response.status_code}")
        
        if response.ok:
            result = response.json()
            print(f"\n✅ Investigation completed successfully!")
            print(f"{'='*60}")
            print(f"Status: {result.get('status')}")
            print(f"IP Analyzed: {result.get('ip_address')}")
            print(f"Execution Time: {result.get('execution_time')}")
            print(f"PDF Report: {result.get('pdf_report')}")
            print(f"{'='*60}")
            
            # Print raw result (truncated)
            raw_result = result.get('raw_result', '')
            if raw_result:
                print(f"\n📄 Investigation Summary (first 500 chars):")
                print("-" * 60)
                print(raw_result[:500] + "..." if len(raw_result) > 500 else raw_result)
            
        else:
            print(f"\n❌ Investigation failed")
            print(f"Error: {response.text}")
            
    except requests.exceptions.Timeout:
        print("⏱️  Request timed out - investigation may still be running")
        print("   Check service logs for progress")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to integration service")
        print("   Make sure service is running on port 8002")
        
    except Exception as e:
        print(f"❌ Error: {e}")


def test_health_first():
    """Quick health check before running investigation"""
    print("🏥 Checking service health...")
    
    try:
        response = requests.get(f"{INTEGRATION_URL}/health", timeout=5)
        if response.ok:
            print("✅ Service is healthy\n")
            return True
        else:
            print(f"⚠️  Service health check failed: {response.status_code}\n")
            return False
    except Exception as e:
        print(f"❌ Cannot reach service: {e}\n")
        return False


if __name__ == "__main__":
    print("🚀 CrewAI Investigation Test\n")
    
    # First check if service is up
    if not test_health_first():
        print("Please start the integration service first:")
        print("  cd services/wazuh-integration")
        print("  python main.py")
        exit(1)
    
    # Run investigation test
    test_crewai_investigation(
        alert_id="test-critical-001",
        ip_address="8.8.8.8"  # Google DNS - safe test IP
    )
    
    print("\n" + "=" * 60)
    print("✅ Test completed!")
    print("=" * 60)