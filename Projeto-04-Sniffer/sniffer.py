import argparse
import logging
import sys
from typing import Optional
from scapy.all import sniff, Packet
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR
from scapy.layers.tls.handshake import TLSClientHello
from scapy.packet import Raw

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("network_audit.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

class NetworkAnalyzer:
    def __init__(self, interface: str):
        self.interface = interface
        self.packet_counts = {"DNS": 0, "HTTP": 0, "HTTPS": 0}

    def _extract_host_from_http(self, packet: Packet) -> Optional[str]:
        try:
            return packet[HTTPRequest].Host.decode().strip()
        except (AttributeError, UnicodeDecodeError):
            return None

    def _analyze_dns(self, packet: Packet):
        if not packet.haslayer(DNSQR):
            return

        query_name = packet[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
        src_ip = packet[IP].src
        
        self.packet_counts["DNS"] += 1
        logging.info(f"[DNS] Query: {query_name} | Origem: {src_ip}")

    def _analyze_http(self, packet: Packet):
        if not packet.haslayer(HTTPRequest):
            return

        host = self._extract_host_from_http(packet) or "Unknown Host"
        path = packet[HTTPRequest].Path.decode("utf-8", errors="ignore")
        method = packet[HTTPRequest].Method.decode("utf-8", errors="ignore")
        src_ip = packet[IP].src

        self.packet_counts["HTTP"] += 1
        logging.info(f"[HTTP] {method} {host}{path} | Origem: {src_ip}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode("utf-8", errors="ignore")
            keywords = ["login", "user", "pass", "token", "auth"]
            
            if any(key in payload.lower() for key in keywords):
                logging.warning(f"[ALERTA CREDENCIAL] Payload Suspeito: {payload[:100]}...")

    def _analyze_tls(self, packet: Packet):
        if not packet.haslayer(TLSClientHello):
            return

        try:
            for extension in packet[TLSClientHello].extensions:
                if hasattr(extension, "servernames") and extension.servernames:
                    domain = extension.servernames[0].servername.decode("utf-8", errors="ignore")
                    src_ip = packet[IP].src
                    
                    self.packet_counts["HTTPS"] += 1
                    logging.info(f"[TLS/SNI] Domínio: {domain} | Origem: {src_ip}")
                    return
        except Exception as e:
            logging.debug(f"Erro ao parsear TLS: {e}")

    def packet_callback(self, packet: Packet):
        if not packet.haslayer(IP):
            return

        if packet.haslayer(DNSQR):
            self._analyze_dns(packet)
        elif packet.haslayer(TLSClientHello):
            self._analyze_tls(packet)
        elif packet.haslayer(HTTPRequest):
            self._analyze_http(packet)

    def start(self):
        logging.info(f"Iniciando captura na interface: {self.interface}")
        try:
            sniff(
                iface=self.interface, 
                prn=self.packet_callback, 
                store=0,
                filter="tcp or udp"
            )
        except PermissionError:
            logging.error("Permissão negada. Execute com 'sudo'.")
        except KeyboardInterrupt:
            logging.info("\nCaptura encerrada pelo usuário.")
            logging.info(f"Resumo da Sessão: {self.packet_counts}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ferramenta de Auditoria de Rede Passiva")
    parser.add_argument("-i", "--interface", required=True, help="Interface de rede (ex: wlan0, eth0)")
    
    args = parser.parse_args()
    
    analyzer = NetworkAnalyzer(interface=args.interface)
    analyzer.start()