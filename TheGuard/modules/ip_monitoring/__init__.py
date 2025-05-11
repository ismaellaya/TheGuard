from .ip_tracker import IPTracker
from .connection_logger import ConnectionLogger
from .abuse_ipdb_integration import AbuseIPDBClient
from .ip_tracker import IPMonitoringModule

def get_ip_tracker() -> IPTracker:
    """Returns a configured IP tracker instance."""
    return IPTracker()

def get_connection_logger() -> ConnectionLogger:
    """Returns a configured connection logger instance."""
    return ConnectionLogger()

def get_abuse_ipdb_client() -> AbuseIPDBClient:
    """Returns a configured AbuseIPDB client instance."""
    return AbuseIPDBClient()

__all__ = [
    'IPTracker',
    'ConnectionLogger',
    'AbuseIPDBClient',
    'get_ip_tracker',
    'get_connection_logger',
    'get_abuse_ipdb_client'
]
