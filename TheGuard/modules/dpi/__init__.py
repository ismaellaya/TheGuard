from .packet_capture import PacketCapture
from .payload_parser import PayloadParser, analyze_payload
from .regex_rules import RegexRules, match_patterns

def get_packet_analyzer() -> PacketCapture:
    """Returns a configured packet analyzer instance."""
    return PacketCapture()

def get_payload_parser() -> PayloadParser:
    """Returns a configured payload parser instance."""
    return PayloadParser()

def get_regex_rules() -> RegexRules:
    """Returns a configured regex rules instance."""
    return RegexRules()

__all__ = [
    'PacketCapture',
    'PayloadParser',
    'RegexRules',
    'analyze_payload',
    'match_patterns',
    'get_packet_analyzer',
    'get_payload_parser',
    'get_regex_rules'
]