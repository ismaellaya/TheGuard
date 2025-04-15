from scapy.all import sniff, IP, TCP, UDP, Raw
import yaml
import queue
import time
import requests
from concurrent.futures import ThreadPoolExecutor
import logging
import threading
from typing import Dict, Any
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
        
        # Configuración DPI
        self.sample_rate = self.config.get('dpi', {}).get('sample_rate', 5)
        self.https_ports = self.config.get('dpi', {}).get('https_ports', [443, 8443])
        self.alert_endpoint = self.config.get('dpi', {}).get('alert_endpoint', 'http://localhost:5000/api/alerts')
        self.alert_timeout = self.config.get('dpi', {}).get('alert_timeout', 5)
        
        # Contadores y estado
        self.packet_count = 0
        
        # Cola de alertas y pool de hilos
        self.alert_queue = queue.Queue()
        self.thread_pool = ThreadPoolExecutor(
            max_workers=self.config.get('dpi', {}).get('thread_pool_size', 4)
        )
        
        # Iniciar thread para procesamiento de alertas
        self.alert_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.alert_thread.start()

    def should_process_packet(self, packet) -> bool:
        """Determina si un paquete debe ser procesado basado en muestreo y filtros"""
        # Incrementar contador global
        self.packet_count += 1
        
        # Aplicar muestreo
        if self.packet_count % self.sample_rate != 0:
            return False
            
        # Verificar si es paquete TCP/IP
        if not (packet.haslayer(TCP) and packet.haslayer(IP)):
            return False
            
        # Filtrar puertos HTTPS
        tcp_layer = packet[TCP]
        if tcp_layer.dport in self.https_ports or tcp_layer.sport in self.https_ports:
            return False
            
        # Verificar si tiene payload
        if not packet.haslayer(Raw):
            return False
            
        return True

    def _send_alert(self, alert_data: Dict[str, Any]):
        """Envía una alerta al endpoint configurado"""
        try:
            response = requests.post(
                self.alert_endpoint,
                json=alert_data,
                timeout=self.alert_timeout
            )
            if response.status_code == 200:
                self.logger.info(f"Alerta enviada exitosamente: {alert_data}")
            else:
                self.logger.error(f"Error enviando alerta: {response.status_code}")
        except Exception as e:
            self.logger.error(f"Error en envío de alerta: {str(e)}")

    def _process_alerts(self):
        """Procesa las alertas en cola de forma asíncrona"""
        while True:
            try:
                alert = self.alert_queue.get()
                if alert is None:  # Señal de terminación
                    break
                self.thread_pool.submit(self._send_alert, alert)
            except Exception as e:
                self.logger.error(f"Error procesando alerta: {str(e)}")

    def start_capture(self):
        """Inicia la captura de paquetes en la interfaz configurada."""
        try:
            self.logger.info(f"Iniciando captura en interfaz {self.config['network']['interface']}")
            sniff(
                iface=self.config['network']['interface'],
                filter=self.config['network']['capture_filter'],
                prn=self.process_packet,
                store=0  # No almacenar paquetes en memoria
            )
        except Exception as e:
            self.logger.error(f"Error al iniciar la captura: {str(e)}")
            raise
        finally:
            self.stop_capture()

    def process_packet(self, packet):
        """Procesa cada paquete capturado."""
        # Aplicar prefiltrado y muestreo
        if not self.should_process_packet(packet):
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
        
        payload = bytes(packet[Raw].load)
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
        
        payload = bytes(packet[Raw].load)
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
            'pattern_matches': matches,
            'timestamp': time.time()
        }
        
        # Registrar en log
        self.logger.warning(f"Actividad sospechosa detectada: {alert}")
        
        # Agregar a la cola de alertas para envío asíncrono
        self.alert_queue.put(alert)

    def stop_capture(self):
        """Detiene la captura de paquetes y limpia recursos."""
        # Señal de terminación para el thread de alertas
        self.alert_queue.put(None)
        
        # Esperar a que terminen los threads
        self.alert_thread.join()
        self.thread_pool.shutdown(wait=True)
        
        self.logger.info("Captura de paquetes detenida")