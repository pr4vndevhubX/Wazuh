"""
Wazuh SIEM Query Tool - Production Ready with Fast IP Search
REFACTORED: Returns ALL alerts with full details for accurate timeline generation
"""

from crewai.tools import BaseTool
import sys
from pathlib import Path
from datetime import datetime, timedelta

sys.path.append(str(Path(__file__).parent.parent))
from utils.alert_storage import AlertStorage
from utils.db_path import get_wazuh_db_path


class WazuhSIEMTool(BaseTool):
    name: str = "Query Wazuh SIEM History"
    description: str = """
    Search Wazuh alerts database for IP-related activity using fast indexed queries.
    Returns COMPLETE alert details including timestamps and descriptions for timeline generation.
    
    Args:
        ip_address: IP address to search (e.g., "192.168.100.133" or "45.135.197.136")
        days: Number of days to look back (default: 30)
    
    Returns:
        Dictionary with:
        - alerts_found: Total count of matching alerts
        - alerts: FULL list of all matching alerts (not truncated)
        - Each alert contains: id, timestamp, rule_id, rule_level, rule_description, 
          agent_name, srcip, dstip, classification, severity
        - summary: Human-readable summary
        - timeline: First/last seen timestamps
        - verdict: Risk assessment
    """

    def _run(self, ip_address: str, days: int = 30) -> dict:
        """
        Execute SIEM query with fast IP column search.
        Returns ALL matching alerts without truncation.
        """
        
        print("\n" + "="*70)
        print("🔍 [SIEM TOOL EXECUTION STARTED]")
        print("="*70)
        print(f"📍 Target IP: {ip_address}")
        print(f"📅 Time Range: Last {days} days")
        
        try:
            # Step 1: Connect to Database
            print("\n[STEP 1] Connecting to Wazuh SQLite Database...")
            alert_storage = AlertStorage(db_path=get_wazuh_db_path())
            print(f"📂 Using Wazuh DB: {get_wazuh_db_path()}")
            print("✅ Database connection successful")
            
            # Step 2: Calculate Time Range
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(days=days)
            print(f"\n[STEP 2] Time Range Calculated:")
            print(f"   Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            print(f"   End:   {end_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
            
            # Step 3: Query Database with Fast IP Search
            print(f"\n[STEP 3] Querying database for IP: {ip_address}")
            print(f"   Search method: Indexed column query (srcip/dstip)")
            raw_alerts = alert_storage.search_alerts_by_ip(ip_address, days=days)
            print(f"✅ Found {len(raw_alerts)} alerts for this IP")
            
            # Step 4: Format Results with FULL Details
            print(f"\n[STEP 4] Formatting alert data with complete details...")
            matching_alerts = []
            
            for alert in raw_alerts:
                # ✅ CRITICAL: Include ALL fields needed for timeline generation
                formatted_alert = {
                    'id': alert['id'],
                    'db_id': alert['id'],
                    'timestamp': alert['timestamp'],  # ✅ Required for timeline
                    'rule_id': alert['rule_id'],
                    'rule_level': alert['rule_level'],
                    'rule_description': alert['rule_description'],  # ✅ Required for timeline
                    'agent_name': alert['agent_name'],
                    'srcip': alert.get('srcip'),
                    'dstip': alert.get('dstip'),
                    'classification': alert.get('classification', 'UNKNOWN'),
                    'severity': alert.get('severity', 'UNKNOWN')
                }
                matching_alerts.append(formatted_alert)
                
                # Log first 5 alerts for verification
                if len(matching_alerts) <= 5:
                    print(f"   ✓ Alert #{len(matching_alerts)}: {alert['timestamp']} - {alert['rule_description'][:60]}")
            
            if len(matching_alerts) > 5:
                print(f"   ... and {len(matching_alerts) - 5} more alerts")
            
            print(f"\n✅ Formatting complete: {len(matching_alerts)} alerts with full details")
            
            # Step 5: Analyze and Classify Results
            print(f"\n[STEP 5] Analyzing alert classifications...")
            
            critical_count = sum(1 for a in matching_alerts if a.get('classification') == 'CRITICAL')
            suspicious_count = sum(1 for a in matching_alerts if a.get('classification') == 'SUSPICIOUS')
            benign_count = sum(1 for a in matching_alerts if a.get('classification') == 'BENIGN')
            unknown_count = len(matching_alerts) - critical_count - suspicious_count - benign_count
            
            print(f"   🔴 CRITICAL:    {critical_count} alerts")
            print(f"   🟡 SUSPICIOUS:  {suspicious_count} alerts")
            print(f"   🟢 BENIGN:      {benign_count} alerts")
            print(f"   ⚪ UNKNOWN:     {unknown_count} alerts")
            
            # Step 6: Build Timeline and Summary
            print(f"\n[STEP 6] Building timeline and summary...")
            
            if matching_alerts:
                # Sort alerts chronologically (oldest first) for timeline
                sorted_alerts = sorted(matching_alerts, key=lambda x: x['timestamp'])
                first_seen = sorted_alerts[0]['timestamp']
                last_seen = sorted_alerts[-1]['timestamp']
                
                # Find most common rule
                rules = [a['rule_description'] for a in matching_alerts]
                most_common = max(set(rules), key=rules.count) if rules else "Unknown"
                
                # Build intelligent summary
                summary = f"Found {len(matching_alerts)} alerts involving {ip_address}. "
                
                if critical_count > 0:
                    summary += f"⚠️ {critical_count} CRITICAL alerts require immediate attention. "
                if suspicious_count > 0:
                    summary += f"{suspicious_count} SUSPICIOUS alerts detected. "
                if benign_count > 0:
                    summary += f"{benign_count} BENIGN alerts logged. "
                
                summary += f"Most common alert: {most_common[:80]}"
                
                # Determine verdict
                if critical_count > 0:
                    verdict = "CRITICAL_THREAT"
                elif suspicious_count > 0:
                    verdict = "SUSPICIOUS_ACTIVITY"
                elif benign_count > 0:
                    verdict = "KNOWN_BENIGN"
                else:
                    verdict = "NEEDS_REVIEW"
                
                timeline = {
                    'first_seen': first_seen,
                    'last_seen': last_seen,
                    'most_common_alert': most_common,
                    'total_alerts': len(matching_alerts)
                }
                
                print(f"   📅 First seen: {first_seen}")
                print(f"   📅 Last seen: {last_seen}")
                print(f"   📊 Most common: {most_common[:60]}")
                
            else:
                summary = f"No alerts found for {ip_address} in the last {days} days."
                verdict = "NEVER_SEEN"
                first_seen = None
                last_seen = None
                most_common = None
                timeline = None
                
                print(f"   ℹ️ No alerts found in database")
            
            # Step 7: Build Final Result
            # ✅ CRITICAL CHANGE: Return ALL alerts, not [:10]
            result = {
                'ip': ip_address,
                'alerts_found': len(matching_alerts),
                'critical_alerts': critical_count,
                'suspicious_alerts': suspicious_count,
                'benign_alerts': benign_count,
                'unknown_alerts': unknown_count,
                'verdict': verdict,
                'alerts': sorted_alerts if matching_alerts else [],  # ✅ Return ALL alerts sorted by time
                'summary': summary,
                'timeline': timeline,
                'time_range': f"Last {days} days",
                'query_metadata': {
                    'total_matching_alerts': len(matching_alerts),
                    'alerts_returned': len(matching_alerts),  # ✅ Confirm all alerts returned
                    'query_time': datetime.now().isoformat(),
                    'search_method': 'indexed_ip_columns',
                    'truncated': False  # ✅ Indicates no truncation
                }
            }
            
            print("\n" + "="*70)
            print("✅ [SIEM TOOL EXECUTION COMPLETED]")
            print("="*70)
            print(f"📊 Summary: {len(matching_alerts)} alerts found")
            print(f"📦 Alerts returned: {len(result['alerts'])} (ALL alerts, no truncation)")
            print(f"🎯 Verdict: {verdict}")
            print("="*70 + "\n")
            
            return result
        
        except Exception as e:
            print(f"\n❌ [ERROR]: {str(e)}")
            import traceback
            traceback.print_exc()
            
            return {
                'ip': ip_address,
                'alerts_found': 0,
                'critical_alerts': 0,
                'suspicious_alerts': 0,
                'benign_alerts': 0,
                'unknown_alerts': 0,
                'verdict': 'ERROR',
                'alerts': [],  # Empty list on error
                'summary': f"Error querying SIEM database: {str(e)}",
                'timeline': None,
                'time_range': f"Last {days} days",
                'error': str(e),
                'query_metadata': {
                    'query_time': datetime.now().isoformat(),
                    'error_occurred': True,
                    'alerts_returned': 0
                }
            }


# ===== TESTING =====
if __name__ == "__main__":
    print("🧪 Testing WazuhSIEMTool - Verifying Full Alert Return...\n")
    
    tool = WazuhSIEMTool()
    
    # Test with known IP
    test_ip = input("Enter IP to test (or press Enter for 192.168.100.133): ").strip()
    if not test_ip:
        test_ip = "192.168.100.133"
    
    print(f"\n{'='*70}")
    print(f"Testing with IP: {test_ip}")
    print(f"{'='*70}\n")
    
    result = tool._run(test_ip, days=30)
    
    print("\n" + "="*70)
    print("📋 FINAL RESULT VERIFICATION:")
    print("="*70)
    print(f"IP: {result['ip']}")
    print(f"Alerts Found: {result['alerts_found']}")
    print(f"Alerts Returned: {len(result['alerts'])}")
    print(f"Verdict: {result['verdict']}")
    print(f"Truncated: {result['query_metadata'].get('truncated', 'N/A')}")
    print(f"\nSummary: {result['summary']}")
    
    # Verify no truncation
    if result['alerts_found'] == len(result['alerts']):
        print("\n✅ SUCCESS: All alerts returned (no truncation)")
    else:
        print(f"\n❌ WARNING: Expected {result['alerts_found']} alerts but got {len(result['alerts'])}")
    
    # Show sample alerts for timeline verification
    if result['alerts']:
        print(f"\n📋 Sample Alerts (for timeline generation):")
        for i, alert in enumerate(result['alerts'][:5], 1):
            print(f"   {i}. {alert['timestamp']} - {alert['rule_description']}")
        
        if len(result['alerts']) > 5:
            print(f"   ... and {len(result['alerts']) - 5} more alerts")
    
    print("="*70)