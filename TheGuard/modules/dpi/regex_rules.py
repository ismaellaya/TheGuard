import re
import logging
from typing import List, Dict, Optional

class RegexRules:
    def __init__(self):
        self.logger = logging.getLogger('dpi.regex_rules')
        
        # Patrones para diferentes tipos de ataques
        self.patterns = {
            'sql_injection': [
                re.compile(r"(\b(union|select|insert|update|delete|drop|alter)\b.*\b(from|into|table|database)\b)", re.IGNORECASE),
                re.compile(r"(\b(or|and)\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
                re.compile(r"('|\")\s*(or|and)\s*('|\")\s*=\s*('|\")", re.IGNORECASE)
            ],
            'command_injection': [
                re.compile(r"(;|\||`)\s*(cat|wget|curl|bash|chmod|rm|mv)\s", re.IGNORECASE),
                re.compile(r"(/bin/sh|\benv\b|\bexec\b)", re.IGNORECASE),
                re.compile(r"(>\s*/dev/null|\d+>\s*&\d+)", re.IGNORECASE)
            ],
            'path_traversal': [
                re.compile(r"(\.\./|\%2e\%2e\%2f|\.\.\%2f)", re.IGNORECASE),
                re.compile(r"(/etc/passwd|/etc/shadow|/proc/self/environ)", re.IGNORECASE)
            ],
            'xss': [
                re.compile(r"(<script>|</script>|javascript:)", re.IGNORECASE),
                re.compile(r"(on(load|click|mouseover|submit|error)=)", re.IGNORECASE),
                re.compile(r"(alert\(|eval\(|document\.cookie)", re.IGNORECASE)
            ],
            'shell_commands': [
                re.compile(r"\b(nc|netcat|ncat)\b.*\b((-e|-c)\s*/bin/(?:ba)?sh)\b", re.IGNORECASE),
                re.compile(r"\b(base64|hex)\b.*\b(decode|encode)\b", re.IGNORECASE)
            ],
            'data_exfiltration': [
                re.compile(r"(SELECT.*INTO\s+OUTFILE)", re.IGNORECASE),
                re.compile(r"(base64[A-Za-z0-9+/]+={0,2})", re.IGNORECASE)
            ],
            'c2_indicators': [
                re.compile(r"(beacon|command|control|slave|master)", re.IGNORECASE),
                re.compile(r"(check[-_]in|heart[-_]beat|report[-_]home)", re.IGNORECASE)
            ]
        }

def match_patterns(payload: bytes) -> List[Dict[str, str]]:
    """
    Analiza un payload en busca de patrones sospechosos.
    
    Args:
        payload: Bytes del payload a analizar
        
    Returns:
        Lista de diccionarios con las coincidencias encontradas
    """
    try:
        # Intentar decodificar el payload
        payload_str = payload.decode('utf-8', errors='ignore')
    except Exception as e:
        logging.error(f"Error decodificando payload: {e}")
        return []

    rules = RegexRules()
    matches = []

    # Buscar coincidencias para cada categoría
    for category, patterns in rules.patterns.items():
        for pattern in patterns:
            if found := pattern.findall(payload_str):
                matches.append({
                    'category': category,
                    'pattern': pattern.pattern,
                    'matches': found
                })

    return matches

def is_suspicious_payload(payload: bytes, threshold: int = 1) -> bool:
    """
    Determina si un payload es sospechoso basado en el número de coincidencias.
    
    Args:
        payload: Bytes del payload a analizar
        threshold: Número mínimo de coincidencias para considerar sospechoso
        
    Returns:
        bool: True si el payload es sospechoso
    """
    matches = match_patterns(payload)
    return len(matches) >= threshold