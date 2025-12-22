from utils.alert_storage import AlertStorage

storage = AlertStorage(db_path="data/wazuh_alerts.db")
stats = storage.get_stats()

print(f"✅ Database connected!")
print(f"Total alerts: {stats['total_alerts']}")
print(f"Unprocessed: {stats['unprocessed']}")