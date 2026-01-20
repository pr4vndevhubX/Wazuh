# import sqlite3
# from pathlib import Path

# # Get project root (IP-Crewai/)
# BASE_DIR = Path(__file__).resolve().parent.parent

# DB_PATH = BASE_DIR / "data" / "wazuh_alerts.db"

# print("Using DB:", DB_PATH)

# conn = sqlite3.connect(DB_PATH)
# cursor = conn.cursor()

# cursor.execute("SELECT full_alert FROM alerts WHERE id = 1")
# result = cursor.fetchone()

# print("Type:", type(result[0]))
# print("First 300 chars:\n", result[0][:300])

# conn.close()

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]  # IP-Crewai/
DB_PATH = BASE_DIR / "data" / "wazuh_alerts.db"

print("DB Path:", DB_PATH)
print("Exists:", DB_PATH.exists())
print("Size:", DB_PATH.stat().st_size)

