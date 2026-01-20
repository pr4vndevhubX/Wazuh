"""
Alert Storage - SQLite Database
Stores Wazuh alerts with IP extraction and processing state tracking
"""

import sqlite3
import json
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple

class AlertStorage:
    """
    SQLite-based storage for Wazuh alerts with intelligent IP extraction
    """
    
    def __init__(self, db_path: str = "data/wazuh_alerts.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        print(f"💾 AlertStorage initialized: {self.db_path}")
    
    def _init_database(self):
        """Create tables with IP extraction support"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main alerts table with extracted IP fields
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wazuh_id TEXT,
                timestamp TEXT NOT NULL,
                rule_id TEXT,
                rule_level INTEGER,
                rule_description TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                srcip TEXT,
                dstip TEXT,
                full_alert TEXT NOT NULL,
                received_at TEXT NOT NULL,
                processed INTEGER DEFAULT 0,
                processed_at TEXT,
                classification TEXT,
                severity TEXT,
                UNIQUE(wazuh_id, timestamp)
            )
        """)
        
        # Processing results table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS processing_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id INTEGER NOT NULL,
                processing_timestamp TEXT NOT NULL,
                classification TEXT,
                severity TEXT,
                confidence REAL,
                reasoning TEXT,
                recommendations TEXT,
                yeti_malicious_count INTEGER,
                anomaly_score REAL,
                FOREIGN KEY (alert_id) REFERENCES alerts(id)
            )
        """)
        
        # Create indexes for fast IP queries
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_srcip 
            ON alerts(srcip)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_dstip 
            ON alerts(dstip)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_processed 
            ON alerts(processed)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_rule_level 
            ON alerts(rule_level)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp 
            ON alerts(timestamp DESC)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_received_at 
            ON alerts(received_at DESC)
        """)
        
        conn.commit()
        conn.close()
        
        print("✅ Database tables initialized with IP extraction support")
    
    def _extract_ips_from_alert(self, alert: Dict) -> Tuple[Optional[str], Optional[str]]:
        """
        Intelligently extract srcip and dstip from Wazuh alert JSON
        Handles multiple possible JSON structures
        
        Returns: (srcip, dstip) tuple
        """
        srcip = None
        dstip = None
        
        # Priority 1: Check 'data' field (most common in Wazuh alerts)
        data = alert.get('data', {})
        if isinstance(data, dict):
            srcip = data.get('srcip') or data.get('src_ip') or data.get('source_ip')
            dstip = data.get('dstip') or data.get('dst_ip') or data.get('destination_ip')
        
        # Priority 2: Check top-level fields
        if not srcip:
            srcip = alert.get('srcip') or alert.get('src_ip') or alert.get('source_ip')
        if not dstip:
            dstip = alert.get('dstip') or alert.get('dst_ip') or alert.get('destination_ip')
        
        # Priority 3: Check decoder fields (firewall/IDS logs)
        if not srcip or not dstip:
            decoder = alert.get('decoder', {})
            if isinstance(decoder, dict):
                if not srcip:
                    srcip = decoder.get('srcip') or decoder.get('src_ip')
                if not dstip:
                    dstip = decoder.get('dstip') or decoder.get('dst_ip')
        
        # Priority 4: Check syscheck/rootcheck fields
        if not srcip or not dstip:
            syscheck = alert.get('syscheck', {})
            if isinstance(syscheck, dict):
                if not srcip:
                    srcip = syscheck.get('srcip')
                if not dstip:
                    dstip = syscheck.get('dstip')
        
        # Priority 5: Parse from full_log field using regex (last resort)
        if not srcip or not dstip:
            full_log = alert.get('full_log', '')
            if full_log:
                # IPv4 pattern
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                found_ips = re.findall(ip_pattern, full_log)
                
                # Filter out invalid IPs (like 0.0.0.0, 255.255.255.255)
                valid_ips = [ip for ip in found_ips if self._is_valid_ip(ip)]
                
                if len(valid_ips) >= 2 and not srcip and not dstip:
                    srcip = valid_ips[0]
                    dstip = valid_ips[1]
                elif len(valid_ips) == 1 and not srcip:
                    srcip = valid_ips[0]
        
        # Validate extracted IPs
        if srcip and not self._is_valid_ip(srcip):
            srcip = None
        if dstip and not self._is_valid_ip(dstip):
            dstip = None
        
        return srcip, dstip
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Validate IPv4 address
        """
        if not ip:
            return False
        
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            
            # Filter out invalid/reserved IPs
            if ip in ['0.0.0.0', '255.255.255.255']:
                return False
            
            return True
        except (ValueError, AttributeError):
            return False
    
    def store_alert(self, alert: Dict) -> int:
        """
        Store a Wazuh alert with automatic IP extraction
        Returns: alert_id (database primary key)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Extract key fields
            wazuh_id = alert.get('id', 'unknown')
            timestamp = alert.get('timestamp', datetime.utcnow().isoformat())
            rule = alert.get('rule', {})
            agent = alert.get('agent', {})
            
            # Extract IPs intelligently
            srcip, dstip = self._extract_ips_from_alert(alert)
            
            cursor.execute("""
                INSERT INTO alerts (
                    wazuh_id, timestamp, rule_id, rule_level, rule_description,
                    agent_name, agent_ip, srcip, dstip, full_alert, 
                    received_at, processed
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """, (
                wazuh_id,
                timestamp,
                rule.get('id', 'unknown'),
                rule.get('level', 0),
                rule.get('description', ''),
                agent.get('name', 'unknown'),
                agent.get('ip', 'unknown'),
                srcip,
                dstip,
                json.dumps(alert),
                datetime.utcnow().isoformat()
            ))
            
            conn.commit()
            alert_id = cursor.lastrowid
            
            # Debug logging for IP extraction
            if srcip or dstip:
                print(f"✅ Stored alert {alert_id} | srcip: {srcip} | dstip: {dstip}")
            else:
                print(f"⚠️  Stored alert {alert_id} | No IPs extracted")
            
            return alert_id
        
        except sqlite3.IntegrityError:
            # Duplicate alert (same wazuh_id + timestamp)
            print(f"⚠️ Duplicate alert: {wazuh_id}")
            return -1
        
        except Exception as e:
            print(f"❌ Error storing alert: {e}")
            conn.rollback()
            return -1
        
        finally:
            conn.close()
    
    def search_alerts_by_ip(self, ip_address: str, days: int = 30) -> List[Dict]:
        """
        FAST: Search alerts by extracted IP fields (srcip or dstip)
        This is the PRIMARY method for IP queries - uses indexed columns
        
        Args:
            ip_address: IP to search for
            days: Number of days to look back
        
        Returns:
            List of matching alert dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        
        # Query using extracted IP columns (FAST - uses indexes)
        cursor.execute("""
            SELECT * FROM alerts
            WHERE (srcip = ? OR dstip = ?)
            AND timestamp >= ?
            ORDER BY timestamp DESC
        """, (ip_address, ip_address, start_time.isoformat()))
        
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to dict
        columns = [
            'id', 'wazuh_id', 'timestamp', 'rule_id', 'rule_level',
            'rule_description', 'agent_name', 'agent_ip', 'srcip', 'dstip',
            'full_alert', 'received_at', 'processed', 'processed_at', 
            'classification', 'severity'
        ]
        
        alerts = []
        for row in rows:
            alert_dict = dict(zip(columns, row))
            alert_dict['full_alert'] = json.loads(alert_dict['full_alert'])
            alerts.append(alert_dict)
        
        print(f"🔍 IP Search: Found {len(alerts)} alerts for {ip_address} (last {days} days)")
        
        return alerts
    
    def get_unprocessed_alerts(self, limit: int = 100) -> List[Dict]:
        """
        Get unprocessed alerts from database
        Returns: List of alert dictionaries
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, full_alert FROM alerts
            WHERE processed = 0
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        alerts = []
        for row in rows:
            alert = json.loads(row[1])
            alert['db_id'] = row[0]  # Add database ID
            alerts.append(alert)
        
        return alerts
    
    def mark_as_processed(self, alert_ids: List[int]):
        """
        Mark alerts as processed
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        placeholders = ','.join('?' * len(alert_ids))
        cursor.execute(f"""
            UPDATE alerts
            SET processed = 1, processed_at = ?
            WHERE id IN ({placeholders})
        """, [datetime.utcnow().isoformat()] + alert_ids)
        
        conn.commit()
        conn.close()
        
        print(f"✅ Marked {len(alert_ids)} alerts as processed")
    
    def store_processing_result(self, alert_id: int, result: Dict):
        """
        Store CrewAI processing results
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO processing_results (
                alert_id, processing_timestamp, classification, severity,
                confidence, reasoning, recommendations,
                yeti_malicious_count, anomaly_score
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_id,
            datetime.utcnow().isoformat(),
            result.get('classification', 'UNKNOWN'),
            result.get('severity', 'UNKNOWN'),
            result.get('confidence', 0),
            result.get('reasoning', ''),
            json.dumps(result.get('recommendations', [])),
            result.get('yeti_malicious_count', 0),
            result.get('anomaly_score', 0)
        ))
        
        # Update alerts table with final classification
        cursor.execute("""
            UPDATE alerts
            SET classification = ?, severity = ?
            WHERE id = ?
        """, (
            result.get('classification'),
            result.get('severity'),
            alert_id
        ))
        
        conn.commit()
        conn.close()
    
    def get_stats(self) -> Dict:
        """
        Get database statistics including IP extraction stats
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute("SELECT COUNT(*) FROM alerts")
        total = cursor.fetchone()[0]
        
        # Processed alerts
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE processed = 1")
        processed = cursor.fetchone()[0]
        
        # Unprocessed alerts
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE processed = 0")
        unprocessed = cursor.fetchone()[0]
        
        # IP extraction stats
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE srcip IS NOT NULL")
        srcip_extracted = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE dstip IS NOT NULL")
        dstip_extracted = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE srcip IS NOT NULL OR dstip IS NOT NULL")
        any_ip_extracted = cursor.fetchone()[0]
        
        # Alerts by severity (last 24 hours)
        cursor.execute("""
            SELECT rule_level, COUNT(*) 
            FROM alerts 
            WHERE timestamp >= datetime('now', '-1 day')
            GROUP BY rule_level
            ORDER BY rule_level DESC
        """)
        severity_dist = cursor.fetchall()
        
        conn.close()
        
        return {
            'total_alerts': total,
            'processed': processed,
            'unprocessed': unprocessed,
            'processing_rate': round(processed / total * 100, 2) if total > 0 else 0,
            'ip_extraction': {
                'srcip_extracted': srcip_extracted,
                'dstip_extracted': dstip_extracted,
                'any_ip_extracted': any_ip_extracted,
                'extraction_rate': round(any_ip_extracted / total * 100, 2) if total > 0 else 0
            },
            'severity_distribution_24h': dict(severity_dist)
        }
    
    def get_recent_alerts(self, limit: int = 10, processed: Optional[bool] = None) -> List[Dict]:
        """
        Get recent alerts (optionally filtered by processed status)
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if processed is None:
            query = "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?"
            params = (limit,)
        else:
            query = "SELECT * FROM alerts WHERE processed = ? ORDER BY timestamp DESC LIMIT ?"
            params = (1 if processed else 0, limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to dict
        columns = [
            'id', 'wazuh_id', 'timestamp', 'rule_id', 'rule_level',
            'rule_description', 'agent_name', 'agent_ip', 'srcip', 'dstip',
            'full_alert', 'received_at', 'processed', 'processed_at', 
            'classification', 'severity'
        ]
        
        alerts = []
        for row in rows:
            alert_dict = dict(zip(columns, row))
            alert_dict['full_alert'] = json.loads(alert_dict['full_alert'])
            alerts.append(alert_dict)
        
        return alerts
    
    def search_alerts(
        self,
        rule_level_min: Optional[int] = None,
        agent_name: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict]:
        """
        Search alerts with filters
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if rule_level_min:
            query += " AND rule_level >= ?"
            params.append(rule_level_min)
        
        if agent_name:
            query += " AND agent_name LIKE ?"
            params.append(f"%{agent_name}%")
        
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Convert to dict
        columns = [
            'id', 'wazuh_id', 'timestamp', 'rule_id', 'rule_level',
            'rule_description', 'agent_name', 'agent_ip', 'srcip', 'dstip',
            'full_alert', 'received_at', 'processed', 'processed_at', 
            'classification', 'severity'
        ]
        
        alerts = []
        for row in rows:
            alert_dict = dict(zip(columns, row))
            alert_dict['full_alert'] = json.loads(alert_dict['full_alert'])
            alerts.append(alert_dict)
        
        return alerts
    
    def get_unique_ips(self, days: int = 7, limit: int = 100) -> Dict:
        """
        Get unique source and destination IPs from recent alerts
        Useful for threat hunting and network analysis
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        start_time = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        # Get unique source IPs
        cursor.execute("""
            SELECT srcip, COUNT(*) as count
            FROM alerts
            WHERE srcip IS NOT NULL
            AND timestamp >= ?
            GROUP BY srcip
            ORDER BY count DESC
            LIMIT ?
        """, (start_time, limit))
        
        srcips = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        # Get unique destination IPs
        cursor.execute("""
            SELECT dstip, COUNT(*) as count
            FROM alerts
            WHERE dstip IS NOT NULL
            AND timestamp >= ?
            GROUP BY dstip
            ORDER BY count DESC
            LIMIT ?
        """, (start_time, limit))
        
        dstips = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
        
        conn.close()
        
        return {
            'source_ips': srcips,
            'destination_ips': dstips,
            'time_range_days': days
        }


# ===== TESTING =====
if __name__ == "__main__":
    print("🧪 Testing AlertStorage with IP extraction...\n")
    
    storage = AlertStorage()
    
    # Test IP extraction with sample alert
    test_alert = {
        "id": "1234",
        "timestamp": "2025-12-17T10:00:00.000Z",
        "rule": {
            "id": "5710",
            "level": 8,
            "description": "SSH brute force attempt"
        },
        "agent": {
            "name": "web-server-01",
            "ip": "10.0.1.50"
        },
        "data": {
            "srcip": "192.168.202.4",
            "dstip": "142.250.67.34"
        },
        "full_log": "SSH failed login from 192.168.202.4"
    }
    
    print("📥 Storing test alert...")
    alert_id = storage.store_alert(test_alert)
    print(f"✅ Alert stored with ID: {alert_id}\n")
    
    # Test IP search
    print("🔍 Searching for IP: 192.168.202.4")
    results = storage.search_alerts_by_ip("192.168.202.4", days=30)
    print(f"✅ Found {len(results)} alerts\n")
    
    # Show stats
    print("📊 Database Statistics:")
    stats = storage.get_stats()
    print(json.dumps(stats, indent=2))