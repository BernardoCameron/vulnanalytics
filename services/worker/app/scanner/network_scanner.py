"""
código que envuelve nmap (usando python-nmap)
"""

import nmap
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger(__name__)

# clases para guardar info
@dataclass
class PortInfo:
    port: int
    protocol: str          # tcp / udp
    state: str             # open / closed / filtered
    service: str           # http, ssh, etc.
    version: str           # version detectada si existe
    product: str           # producto detectado
    vulnerabilities_nse: dict = field(default_factory=dict) # resultados de scripts vuln de Nmap


@dataclass
class HostResult:
    ip: str
    hostname: str
    state: str             # up / down
    os_guess: str          # mejor guess del OS
    ports: list[PortInfo] = field(default_factory=list)
    raw: dict = field(default_factory=dict)   # output crudo de nmap por si se necesita


@dataclass
class ScanResult:
    target: str            # input original (IP o segmento)
    scan_type: str         # "single" | "network"
    hosts_scanned: int
    hosts_up: int
    results: list[HostResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

# helpers para validar
def _is_single_host(target: str) -> bool:
    """valida q sea una sola ip"""
    try:
        network = ipaddress.ip_network(target, strict=False)
        return network.num_addresses == 1
    except ValueError:
        # Si no es notación CIDR, intentamos parsearlo como IP pura
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            raise ValueError(f"Target inválido: '{target}'. Usa una IP o un segmento CIDR.")


def _parse_host(nm: nmap.PortScanner, ip: str) -> HostResult:
    """Extrae la info de un host ya escaneado del objeto PortScanner."""
    hostname = ""
    if nm[ip].hostname():
        hostname = nm[ip].hostname()

    state = nm[ip].state()

    # OS detection (puede no estar disponible sin -O y root)
    os_guess = "unknown"
    try:
        os_matches = nm[ip].get("osmatch", [])
        if os_matches:
            os_guess = os_matches[0].get("name", "unknown")
    except Exception:
        pass

    ports: list[PortInfo] = []
    for proto in nm[ip].all_protocols():
        for port in sorted(nm[ip][proto].keys()):
            p = nm[ip][proto][port]
            ports.append(PortInfo(
                port=port,
                protocol=proto,
                state=p.get("state", ""),
                service=p.get("name", ""),
                version=p.get("version", ""),
                product=p.get("product", ""),
                vulnerabilities_nse=p.get("script", {}),
            ))

    return HostResult(
        ip=ip,
        hostname=hostname,
        state=state,
        os_guess=os_guess,
        ports=ports,
        raw=dict(nm[ip]),
    )

class NetworkScanner:
    """
    Wrapper de python-nmap para escaneo de hosts individuales o segmentos.

    Args:
        ports:       Rango de puertos a escanear. Default: top 1000.
        arguments:   Argumentos nmap adicionales. Default: detección de versiones y scripts básicos.
        sudo:        Si True, ejecuta nmap con sudo (necesario para SYN scan y OS detection).
    """

    DEFAULT_PORTS = "1-1024,8080,8443,3306,5432,6379,27017,9200"
    DEFAULT_ARGS  = "-sV --script vuln --open"   # version + motor de vulnerabilidades agressivo

    def __init__(
        self,
        ports: str = DEFAULT_PORTS,
        arguments: str = DEFAULT_ARGS,
        sudo: bool = False,
    ):
        self.ports = ports
        self.arguments = arguments
        self.sudo = sudo
        
        try:
            self.nm = nmap.PortScanner()
            self.nmap_available = True
        except nmap.PortScannerError as e:
            logger.warning(f"no hay nmap instalado. usando datos falsos para desarrollo. error: {e}")
            self.nm = None
            self.nmap_available = False

    def scan_host(self, ip: str) -> HostResult:
        """escanea a lo crudo la ip"""
        logger.info(f"Escaneando host: {ip} | puertos: {self.ports} | args: {self.arguments}")
        try:
            self.nm.scan(
                hosts=ip,
                ports=self.ports,
                arguments=self.arguments,
                sudo=self.sudo,
            )
            if ip not in self.nm.all_hosts():
                logger.warning(f"Host {ip} no respondió.")
                return HostResult(ip=ip, hostname="", state="down", os_guess="unknown")
            return _parse_host(self.nm, ip)
        except nmap.PortScannerError as e:
            logger.error(f"error de nmap escaneando {ip}: {e}")
            raise

    def discover_hosts(self, network: str) -> list[str]:
        """hace pin a todo para ver qien esta activo antes de escanearlo (asi no perdemos tanto rato)"""
        logger.info(f"Haciendo discovery en segmento: {network}")
        try:
            self.nm.scan(hosts=network, arguments="-sn", sudo=self.sudo)
            alive = [h for h in self.nm.all_hosts() if self.nm[h].state() == "up"]
            logger.info(f"Hosts vivos encontrados: {len(alive)} → {alive}")
            return alive
        except nmap.PortScannerError as e:
            logger.error(f"fallo ubicar vivos en {network}: {e}")
            raise

    def scan(self, target: str) -> ScanResult:
        """punto de inicio para escaneos"""
        errors: list[str] = []
        results: list[HostResult] = []

        if not self.nmap_available:
            logger.info(f"haciendo de cuenta que funcionó en nmap a {target}")
            return ScanResult(
                target=target,
                scan_type="mock",
                hosts_scanned=1,
                hosts_up=1,
                results=[
                    HostResult(
                        ip=target,
                        hostname="test-mock-server",
                        state="up",
                        os_guess="MOCK-OS",
                        ports=[
                            PortInfo(port=80, protocol="tcp", state="open", service="http", version="1.1", product="Mocked Web API"),
                            PortInfo(port=443, protocol="tcp", state="open", service="https", version="1.3", product="Mocked Secure API")
                        ]
                    )
                ]
            )

        single = _is_single_host(target)
        scan_type = "single" if single else "network"

        if single:
            # Normalizamos por si viene como /32
            ip = str(ipaddress.ip_network(target, strict=False).network_address)
            try:
                host_result = self.scan_host(ip)
                results.append(host_result)
            except Exception as e:
                errors.append(str(e))

        else:
            # Discovery primero
            try:
                alive_hosts = self.discover_hosts(target)
            except Exception as e:
                errors.append(f"Discovery falló: {e}")
                alive_hosts = []

            # Escanear cada host vivo
            for ip in alive_hosts:
                try:
                    host_result = self.scan_host(ip)
                    results.append(host_result)
                except Exception as e:
                    logger.error(f"Error escaneando {ip}: {e}")
                    errors.append(f"{ip}: {e}")

        hosts_up = sum(1 for r in results if r.state == "up")

        return ScanResult(
            target=target,
            scan_type=scan_type,
            hosts_scanned=len(results),
            hosts_up=hosts_up,
            results=results,
            errors=errors,
        )