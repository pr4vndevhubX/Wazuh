from pathlib import Path

def get_wazuh_db_path():
    """
    Always return the REAL wazuh_alerts.db path
    regardless of where the script is run from.
    """
    base_dir = Path(__file__).resolve().parents[1]  # IP-Crewai/
    db_path = base_dir / "data" / "wazuh_alerts.db"

    if not db_path.exists():
        raise FileNotFoundError(f"Wazuh DB not found at: {db_path}")

    return str(db_path)
