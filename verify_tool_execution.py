"""
Verification Script: Test if SIEM tool actually queries database
Run this before production to ensure no hallucination
"""

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from tools.wazuh_siem_tool import WazuhSIEMTool
from utils.alert_storage import AlertStorage

def verify_tool_execution():
    """
    Test SIEM tool with known data to verify it queries DB correctly
    """
    
    print("="*70)
    print("🧪 SIEM TOOL VERIFICATION TEST")
    print("="*70)
    
    # Test 1: Query existing IP (should find alerts)
    print("\n[TEST 1] Querying IP that EXISTS in database...")
    print("Expected: Should find alerts and log database query")
    
    tool = WazuhSIEMTool()
    result1 = tool._run("45.135.197.136", days=30)
    
    print(f"\n[TEST 1 RESULT]:")
    print(f"   Alerts Found: {result1['alerts_found']}")
    print(f"   Critical: {result1.get('critical_alerts', 0)}")
    print(f"   Tool executed: {'✅ YES' if 'query_metadata' in result1 else '❌ NO (HALLUCINATED!)'}")
    
    # Test 2: Query non-existent IP (should find 0 alerts)
    print("\n" + "="*70)
    print("[TEST 2] Querying IP that DOES NOT EXIST in database...")
    print("Expected: Should find 0 alerts (not estimate or guess)")
    
    result2 = tool._run("1.2.3.4", days=30)
    
    print(f"\n[TEST 2 RESULT]:")
    print(f"   Alerts Found: {result2['alerts_found']}")
    print(f"   Should be 0: {'✅ CORRECT' if result2['alerts_found'] == 0 else '❌ WRONG (HALLUCINATED!)'}")
    
    # Test 3: Verify database was actually queried
    print("\n" + "="*70)
    print("[TEST 3] Verifying database connection...")
    
    storage = AlertStorage(db_path="data/wazuh_alerts.db")
    stats = storage.get_stats()
    
    print(f"\n[TEST 3 RESULT]:")
    print(f"   Total alerts in DB: {stats['total_alerts']}")
    print(f"   Database accessible: {'✅ YES' if stats['total_alerts'] >= 0 else '❌ NO'}")
    
    # Test 4: Compare tool results with direct DB query
    print("\n" + "="*70)
    print("[TEST 4] Cross-verifying tool output vs direct DB query...")
    
    # Direct DB query
    direct_alerts = storage.search_alerts(limit=1000)
    direct_match_count = sum(1 for a in direct_alerts if "45.135.197.136" in str(a['full_alert']).lower())
    
    print(f"\n[TEST 4 RESULT]:")
    print(f"   Direct DB query: {direct_match_count} alerts")
    print(f"   Tool reported: {result1['alerts_found']} alerts")
    print(f"   Match: {'✅ VERIFIED' if direct_match_count == result1['alerts_found'] else '❌ MISMATCH!'}")
    
    # Final Verdict
    print("\n" + "="*70)
    print("📋 VERIFICATION SUMMARY")
    print("="*70)
    
    all_passed = (
        'query_metadata' in result1 and
        result2['alerts_found'] == 0 and
        stats['total_alerts'] >= 0 and
        direct_match_count == result1['alerts_found']
    )
    
    if all_passed:
        print("✅ ALL TESTS PASSED - Tool is querying database correctly")
        print("✅ No hallucination detected")
        print("✅ Safe to use in production")
    else:
        print("❌ SOME TESTS FAILED - Review logs above")
        print("❌ DO NOT USE until issues are resolved")
    
    print("="*70 + "\n")


if __name__ == "__main__":
    verify_tool_execution()