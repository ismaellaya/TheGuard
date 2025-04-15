import base64
import binascii
import logging
import re
import zlib
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import unquote

class PayloadParser:
    def __init__(self):
        self.logger = logging.getLogger('dpi.payload_parser')
        
        # Protocolos comunes y sus puertos predeterminados
        self.protocol_ports = {
            'http': [80, 8080, 8000],
            'https': [443, 8443],
            'ftp': [20, 21],
            'ssh': [22],
            'telnet': [23],
            'smtp': [25, 587],
            'dns': [53],
            'pop3': [110],
            'imap': [143],
            'sql': [1433, 3306, 5432],
            'rdp': [3389]
        }

    def identify_protocol(self, sport: int, dport: int) -> Optional[str]:
        """
        Identifica el protocolo basado en los puertos origen y destino.
        """
        for protocol, ports in self.protocol_ports.items():
            if sport in ports or dport in ports:
                return protocol
        return None

    def try_decode_base64(self, data: bytes) -> Optional[str]:
        """
        Intenta decodificar datos en base64.
        """
        try:
            # Eliminar caracteres no válidos de base64
            cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', data.decode('utf-8', 'ignore'))
            # Ajustar padding si es necesario
            padding = 4 - (len(cleaned) % 4)
            if padding != 4:
                cleaned += '=' * padding
            return base64.b64decode(cleaned).decode('utf-8', 'ignore')
        except:
            return None

    def try_decompress(self, data: bytes) -> Optional[bytes]:
        """
        Intenta descomprimir datos (gzip, deflate).
        """
        try:
            return zlib.decompress(data)
        except:
            try:
                return zlib.decompress(data, wbits=16+zlib.MAX_WBITS)  # gzip
            except:
                try:
                    return zlib.decompress(data, wbits=-zlib.MAX_WBITS)  # raw deflate
                except:
                    return None

    def parse_http(self, payload: bytes) -> Dict:
        """
        Analiza payloads HTTP.
        """
        try:
            # Dividir headers y body
            parts = payload.split(b'\r\n\r\n', 1)
            headers = parts[0].decode('utf-8', 'ignore')
            body = parts[1] if len(parts) > 1 else b''
            
            # Parsear primera línea y headers
            header_lines = headers.split('\r\n')
            request_line = header_lines[0]
            header_dict = {}
            
            for line in header_lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    header_dict[key.lower()] = value
            
            return {
                'request_line': request_line,
                'headers': header_dict,
                'body': body,
                'body_decoded': self.try_decode_base64(body) or body.decode('utf-8', 'ignore')
            }
        except Exception as e:
            self.logger.error(f"Error parsing HTTP: {e}")
            return {}

    def parse_binary(self, payload: bytes) -> Dict:
        """
        Analiza payloads binarios buscando patrones conocidos.
        """
        result = {
            'hex': payload.hex(),
            'possible_encoding': None,
            'decoded_content': None,
            'analysis': []
        }
        
        # Buscar secuencias conocidas
        if payload.startswith(b'MZ'):
            result['analysis'].append('Possible Windows executable')
        elif payload.startswith(b'%PDF'):
            result['analysis'].append('PDF document')
        elif payload.startswith(b'\x7FELF'):
            result['analysis'].append('ELF binary')
        
        # Intentar decodificar si parece base64
        if decoded := self.try_decode_base64(payload):
            result['possible_encoding'] = 'base64'
            result['decoded_content'] = decoded
        
        # Intentar descomprimir
        if decompressed := self.try_decompress(payload):
            result['analysis'].append('Compressed data found')
            try:
                result['decompressed'] = decompressed.decode('utf-8', 'ignore')
            except:
                result['decompressed'] = decompressed.hex()
        
        return result

def analyze_payload(payload: bytes) -> Dict[str, Union[str, List, Dict]]:
    """
    Analiza un payload y retorna información detallada sobre su contenido.
    
    Args:
        payload: Bytes del payload a analizar
        
    Returns:
        Diccionario con el análisis del payload
    """
    parser = PayloadParser()
    result = {
        'size': len(payload),
        'analysis': [],
        'decoded': None,
        'threats': []
    }
    
    # Análisis básico del contenido
    try:
        # Intentar decodificar como texto
        text = payload.decode('utf-8', 'ignore')
        result['decoded'] = text
        
        # Si parece HTTP
        if text.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
            result['protocol'] = 'http'
            result['parsed'] = parser.parse_http(payload)
        else:
            # Análisis binario
            result['parsed'] = parser.parse_binary(payload)
            
        # Identificar amenazas comunes
        if any(pattern in text.lower() for pattern in ['password', 'pass', 'pwd']):
            result['threats'].append('Possible password in cleartext')
        if re.search(r'\b\d{16}\b', text):
            result['threats'].append('Possible credit card number')
        if re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', text):
            result['threats'].append('Email address found')
            
    except UnicodeDecodeError:
        # Si no es texto, hacer análisis binario
        result['analysis'].append('Binary content')
        result['parsed'] = parser.parse_binary(payload)
    
    return result