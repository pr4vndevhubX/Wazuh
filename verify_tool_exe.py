"""
Wazuh SIEM IP Verification Tool (Last 30 Days)
- Uses extracted IP columns (FAST)
- Works for public & private IPs
- Production SOC safe
"""

import ipaddress
from datetime import datetime, timedelta
from utils.alert_storage import AlertStorage
from utils.db_path import get_wazuh_db_path

def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def verify_ip_in_wazuh_db(ip: str, days: int = 30):
    print("=" * 75)
    print("🔍 WAZUH SIEM IP VERIFICATION")
    print("=" * 75)

    print(f"\n[INPUT]")
    print(f"   IP Address : {ip}")
    print(f"   Time Range : Last {days} days")
    print(f"   IP Type    : {'Private (Internal)' if is_private_ip(ip) else 'Public (External)'}")

    # Initialize DB
    storage = AlertStorage(db_path=get_wazuh_db_path())

    # ✅ FIX: Use the correct method
    print("\n[STEP 1] Querying Wazuh DB...")
    matched_alerts = storage.search_alerts_by_ip(ip, days=days)

    # Results
    print("\n[RESULT]")
    if matched_alerts:
        print(f"✅ IP FOUND in Wazuh DB")
        print(f"   Total Alerts : {len(matched_alerts)}")

        print("\n[ALERT DETAILS]")
        for a in matched_alerts[:5]:
            print(
                f" - Time: {a['timestamp']} | "
                f"Rule: {a['rule_description']} | "
                f"Level: {a['rule_level']}"
            )

        if len(matched_alerts) > 5:
            print(f"   ... {len(matched_alerts) - 5} more alerts")
    else:
        print("⚠️ IP NOT FOUND in Wazuh DB (last 30 days)")
        print("➡ This does NOT mean safe — proceeding to Threat Intel check")

    print("\n" + "=" * 75)
    print("✅ VERIFICATION COMPLETE")
    print("=" * 75)

if __name__ == "__main__":
    user_ip = input("\nEnter IP address to verify: ").strip()
    verify_ip_in_wazuh_db(user_ip, days=30)