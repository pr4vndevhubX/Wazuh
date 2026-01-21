#!/usr/bin/env python3
"""
Test script to verify Wazuh Integration Service
Sends simulated alerts to test routing logic
"""

import requests
import json
import time
from datetime import datetime


# ===== TEST CONFIGURATION =====
INTEGRATION_URL = "http://localhost:8002"
API_KEY = "Apkl3@Jfyg2"


def create_test_alert(level: int, ip: str, rule_id: str = "100001") -> dict:
    """Create a simulated Wazuh alert"""
    return {
        "id": f"test-alert-{int(time.time())}",
        "timestamp": datetime.now().isoformat(),
        "rule": {
            "level": level,
            "description": f"Test alert - Level {level} - Simulated attack from {ip}",
            "id": rule_id,
            "groups": ["test", "authentication_failed"]
        },
        "data": {
            "srcip": ip,
            "dstip": "192.168.1.100"
        },
        "agent": {
            "name": "test-agent",
            "id": "001"
        }
    }


def send_alert(alert: dict, test_name: str):
    """Send alert to integration service"""
    print(f"\n{'='*60}")
    print(f"🧪 TEST: {test_name}")
    print(f"{'='*60}")
    print(f"Alert Level: {alert['rule']['level']}")
    print(f"Source IP: {alert['data']['srcip']}")
    
    try:
        response = requests.post(
            f"{INTEGRATION_URL}/webhook",
            json=alert,
            headers={
                "Content-Type": "application/json",
                "X-API-Key": API_KEY
            },
            timeout=30
        )
        
        print(f"\n📡 Response Status: {response.status_code}")
        
        if response.ok:
            result = response.json()
            print(f"✅ Response:")
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ Error: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ ERROR: Cannot connect to integration service")
        print("   Make sure service is running on port 8002")
    except Exception as e:
        print(f"❌ ERROR: {e}")


def test_health_check():
    """Test health endpoint"""
    print(f"\n{'='*60}")
    print(f"🏥 HEALTH CHECK")
    print(f"{'='*60}")
    
    try:
        response = requests.get(f"{INTEGRATION_URL}/health", timeout=5)
        if response.ok:
            print(f"✅ Service is healthy")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"❌ Health check failed: {response.status_code}")
    except Exception as e:
        print(f"❌ Health check error: {e}")


def main():
    """Run all tests"""
    
    print("🚀 Wazuh Integration Service - Test Suite")
    print("=" * 60)
    
    # Test 1: Health check
    test_health_check()
    
    time.sleep(1)
    
    # Test 2: Low severity (should be archived)
    send_alert(
        create_test_alert(level=3, ip="10.0.0.1"),
        "Level 3 - Should be ARCHIVED"
    )
    
    time.sleep(1)
    
    # Test 3: Medium severity (dashboard only)
    send_alert(
        create_test_alert(level=6, ip="10.0.0.2"),
        "Level 6 - Should go to DASHBOARD ONLY"
    )
    
    time.sleep(1)
    
    # Test 4: High severity (LLM triage)
    send_alert(
        create_test_alert(level=8, ip="8.8.8.8"),
        "Level 8 - Should trigger LLM TRIAGE"
    )
    
    time.sleep(1)
    
    # Test 5: Critical severity (full pipeline)
    send_alert(
        create_test_alert(level=12, ip="45.142.120.10"),
        "Level 12 - Should trigger FULL PIPELINE + FLAG"
    )
    
    time.sleep(1)
    
    # Test 6: Invalid API key
    print(f"\n{'='*60}")
    print(f"🔒 TEST: Invalid API Key")
    print(f"{'='*60}")
    
    try:
        response = requests.post(
            f"{INTEGRATION_URL}/webhook",
            json=create_test_alert(level=10, ip="1.1.1.1"),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": "WRONG_KEY"
            },
            timeout=5
        )
        print(f"Status: {response.status_code}")
        print(f"Expected: 401 Unauthorized")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    print(f"\n{'='*60}")
    print("✅ All tests completed!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Check logs to see alert routing")
    print("2. Verify services were called correctly")
    print("3. Test CrewAI investigation endpoint: /investigate/{alert_id}")


if __name__ == "__main__":
    main()