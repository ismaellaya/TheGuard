from scapy.all import sniff, IP, TCP, UDP
import yaml
from concurrent.futures import ThreadPoolExecutor
import logging
from .payload_parser import analyze_payload
from .regex_rules import match_patterns

class PacketCapture:
    def __init__(self):
        # Cargar configuración
        with open('config/global_config.yaml', 'r') as f:
            self.config = yaml.safe_load(f)
        
        # Configurar logging
        logging.basicConfig(
            filename=self.config['logging']['file'],
            level=getattr(logging, self.config['logging']['level']),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('dpi.packet_capture')
        
        # Pool de hilos para análisis paralelo
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
        
    def start_capture(self):
        """Inicia la captura de paquetes en la interfaz configurada."""
        try:
            self.logger.info(f"Iniciando captura en interfaz {self.config['network']['interface']}")
            sniff(
                iface=self.config['network']['interface'],
                filter=self.config['network']['capture_filter'],
                prn=self.process_packet
            )
        except Exception as e:
            self.logger.error(f"Error al iniciar la captura: {str(e)}")
            raise

    def process_packet(self, packet):
        """Procesa cada paquete capturado."""
        if not packet.haslayer(IP):
            return

        try:
            # Análisis asíncrono del paquete
            self.thread_pool.submit(self._analyze_packet, packet)
        except Exception as e:
            self.logger.error(f"Error procesando paquete: {str(e)}")

    def _analyze_packet(self, packet):
        """Análisis detallado del paquete."""
        # Extraer información básica
        ip_info = {
            'src': packet[IP].src,
            'dst': packet[IP].dst,
            'proto': packet[IP].proto
        }

        # Analizar payload según el protocolo
        if packet.haslayer(TCP):
            self._analyze_tcp(packet, ip_info)
        elif packet.haslayer(UDP):
            self._analyze_udp(packet, ip_info)

    def _analyze_tcp(self, packet, ip_info):
        """Análisis específico para paquetes TCP."""
        tcp_info = {
            'sport': packet[TCP].sport,
            'dport': packet[TCP].dport,
            'flags': packet[TCP].flags
        }
        
        # Analizar payload si existe
        if packet[TCP].payload:
            payload = bytes(packet[TCP].payload)
            if len(payload) > 0:
                # Analizar contenido del payload
                threats = analyze_payload(payload)
                # Buscar patrones sospechosos
                matches = match_patterns(payload)
                
                if threats or matches:
                    self._report_suspicious_activity(ip_info, tcp_info, threats, matches)

    def _analyze_udp(self, packet, ip_info):
        """Análisis específico para paquetes UDP."""
        udp_info = {
            'sport': packet[UDP].sport,
            'dport': packet[UDP].dport
        }
        
        # Analizar payload si existe
        if packet[UDP].payload:
            payload = bytes(packet[UDP].payload)
            if len(payload) > 0:
                threats = analyze_payload(payload)
                matches = match_patterns(payload)
                
                if threats or matches:
                    self._report_suspicious_activity(ip_info, udp_info, threats, matches)

    def _report_suspicious_activity(self, ip_info, proto_info, threats, matches):
        """Reporta actividad sospechosa detectada."""
        alert = {
            'source_ip': ip_info['src'],
            'dest_ip': ip_info['dst'],
            'protocol': ip_info['proto'],
            'source_port': proto_info.get('sport'),
            'dest_port': proto_info.get('dport'),
            'threats': threats,
            'pattern_matches': matches
        }
        
        self.logger.warning(f"Actividad sospechosa detectada: {alert}")
        # TODO: Enviar alerta al dashboard

    def stop_capture(self):
        """Detiene la captura de paquetes y limpia recursos."""
        self.thread_pool.shutdown(wait=True)
        self.logger.info("Captura de paquetes detenida")