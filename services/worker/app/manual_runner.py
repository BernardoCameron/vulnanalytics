import sys
import json
import logging
import datetime
from dataclasses import dataclass, asdict

# se importan los escaneres
from scanner.network_scanner import NetworkScanner
from scanner.hardening_scanner import HardeningScanner
from scanner.vuln_scanner_gvm import GVMScanner

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

class DataclassEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)
@dataclass
class FullAuditReport:
    job_id: str
    target: str
    timestamp: str       
    timestamp_end: str
    duration_seconds: float
    network_scan: dict   
    hardening_scan: dict 
    vulnerability_scan: dict

def run_full_audit(target: str, credentials: dict = None) -> FullAuditReport:
    """corre todo junto (nmap y hardening) y devuelve el objeto"""
    start_time = datetime.datetime.now()
    logger.info(f"Target a escanear: {target} - empezando")

    logger.info("Iniciando escaneo de red (Nmap)")
    net_scanner = NetworkScanner(ports="1-1024", arguments="-T4 --open", sudo=False)
    net_result = net_scanner.scan(target)

    logger.info("Iniciando escaneo de configuracion (Hardening)")
    hard_scanner = HardeningScanner()
    hard_result = hard_scanner.scan()

    logger.info("Iniciando escaneo de vulnerabilidades (GVM/OpenVAS)")
    
    # como GVM esta en otro docker, desde el worker buscamos el host local 
    gvm_scanner = GVMScanner(gvm_host="host.docker.internal", gvm_port=9390, user="admin", password="admin")
    gvm_result = gvm_scanner.scan(target, credentials=credentials)

    end_time = datetime.datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    logger.info(f"tiempo q tardo: {duration}s")
    
    job_id = f"job-{start_time.strftime('%Y%m%d%H%M%S')}"

    report = FullAuditReport(
        job_id=job_id,
        target=target,
        timestamp=start_time.isoformat(),
        timestamp_end=end_time.isoformat(),
        duration_seconds=round(duration, 2),
        network_scan=asdict(net_result),
        hardening_scan=asdict(hard_result),
        vulnerability_scan=asdict(gvm_result)
    )

    return report

def main():
    if len(sys.argv) < 2:
        print("uso: python manual_runner.py <ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    final_report = run_full_audit(target_ip)

    output_filename = "audit_report.json"
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(asdict(final_report), f, indent=4, cls=DataclassEncoder, ensure_ascii=False)
    
    logger.info(f"finalizado. el json se guardo en: {output_filename}")


if __name__ == "__main__":
    main()
