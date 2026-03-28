"""
modulo gvm que actua como proxy entre el worker y el servidor central de openvas
"""

import logging
import socket
from dataclasses import dataclass, field
from typing import List

# Librerias autenticas de GVM
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.errors import GvmError

logger = logging.getLogger(__name__)

@dataclass
class Vulnerability:
    cve: str
    severity: float
    name: str
    description: str

@dataclass
class VulnScanResult:
    target: str
    status: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

class GVMScanner:
    """conector a la base de herramientas externas (motor gvm/nessus)"""
    def __init__(self, gvm_host="localhost", gvm_port=9390, user="admin", password="admin"):
        # Notar que immauss/openvas Docker usa admin/admin por defecto al crearse.
        self.gvm_host = gvm_host
        self.gvm_port = gvm_port
        self.user = user
        self.password = password
        
    def scan(self, target_ip: str, credentials: dict = None) -> VulnScanResult:
        logger.info(f"Iniciando conexion con GVM en {self.gvm_host}:{self.gvm_port} para {target_ip}")
        
        try:
            # INTERACCION REAL CON GVM API
            # Nos conectamos al Socket TLS del demonio ospd/gvmd
            connection = TLSConnection(hostname=self.gvm_host, port=self.gvm_port)
            
            with Gmp(connection=connection) as gmp:
                logger.info("Autenticando con API GMP...")
                gmp.authenticate(self.user, self.password)
                logger.info("Conexion GMP establecida")
                
                import lxml.etree as etree
                import time

                # 1. Encontrar el config de 'Full and fast'
                configs = gmp.get_scan_configs()
                configs_tree = etree.fromstring(configs)
                config_id = None
                for config in configs_tree.xpath('//config'):
                    if config.find('name') is not None and config.find('name').text == "Full and fast":
                        config_id = config.get('id')
                        break
                
                if not config_id:
                    # Fallback UUID for Full and Fast config
                    config_id = "daba56c8-73ec-11df-a475-002264764cea"
                    
                # 1.5 Buscar Port List (Necesario en versiones Slim)
                logger.info("Buscando lista de puertos (Port List)...")
                port_lists_xml = gmp.get_port_lists()
                pl_tree = etree.fromstring(port_lists_xml)
                port_list_id = None
                for pl in pl_tree.xpath('//port_list'):
                    port_list_id = pl.get('id')
                    break
                
                if not port_list_id:
                    port_list_id = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5" # All IANA assigned TCP
                    
                # 1.8 Buscar Scanner (Requerido en GMPv224+)
                logger.info("Buscando Scanner (OpenVAS)...")
                scanners_xml = gmp.get_scanners()
                scanner_tree = etree.fromstring(scanners_xml)
                scanner_id = None
                for sc in scanner_tree.xpath('//scanner'):
                    if sc.find('name') is not None and "OpenVAS" in sc.find('name').text:
                         scanner_id = sc.get('id')
                         break
                
                if not scanner_id:
                     scanner_id = "08b69003-5fc2-4037-a479-93b440211c73" # OpenVAS Default
                
                # 1.9 Vinculacion de Credenciales (Escaneo Autenticado)
                smb_credential_id = None
                ssh_credential_id = None
                
                if credentials:
                    logger.info("Registrando credenciales para escaneo autenticado en GVM...")
                    cred_type = credentials.get("type", "smb").lower()
                    username = credentials.get("username", "")
                    password = credentials.get("password", "")
                    
                    try:
                        cred_res = gmp.create_credential(
                            name=f"WorkerCred_{target_ip}_{int(time.time())}",
                            credential_type="up", # "up" = Username/Password default en OpenVAS
                            login=username,
                            password=password
                        )
                        cred_tree = etree.fromstring(cred_res)
                        if cred_tree.get('status') == "201":
                            if cred_type == "smb":
                                smb_credential_id = cred_tree.get('id')
                            elif cred_type == "ssh":
                                ssh_credential_id = cred_tree.get('id')
                            logger.info(f"Credencial {cred_type.upper()} vinculada correctamente. ID: {cred_tree.get('id')}")
                        else:
                            logger.warning(f"No se pudo crear la credencial en GVM: {cred_res}")
                    except Exception as e:
                        logger.error(f"Fallo programando la credencial en GMP: {e}")
                
                # 2. Crear Target Autenticado
                target_name = f"WorkerTarget_{target_ip}_{int(time.time())}"
                logger.info(f"Creando target en GVM para la IP: {target_name} con port_list={port_list_id}")
                
                target_kwargs = {
                    "name": target_name,
                    "hosts": [target_ip],
                    "port_list_id": port_list_id
                }
                
                # Vincular llaves
                if smb_credential_id:
                     target_kwargs["smb_credential_id"] = smb_credential_id
                if ssh_credential_id:
                     target_kwargs["ssh_credential_id"] = ssh_credential_id
                     
                target_res = gmp.create_target(**target_kwargs)
                
                target_tree = etree.fromstring(target_res)
                if target_tree.get('status') != "201":
                     raise Exception(f"GVM rechazo la creacion del target. Respuesta xml: {target_res}")
                target_id = target_tree.get('id')
                
                # 3. Crear Tarea
                logger.info(f"Creando tarea de escaneo (Task) con scanner_id={scanner_id}...")
                task_res = gmp.create_task(
                     name=f"WorkerScan_{target_ip}", 
                     config_id=config_id, 
                     target_id=target_id, 
                     scanner_id=scanner_id
                )
                task_tree = etree.fromstring(task_res)
                if task_tree.get('status') != "201":
                     raise Exception(f"GVM rechazo la creacion de la tarea. Respuesta xml: {task_res}")
                task_id = task_tree.get('id')
                
                # 4. Iniciar Tarea
                logger.info("Iniciando escaneo de vulnerabilidades GVM. Esto tomara varios minutos...")
                gmp.start_task(task_id)
                
                # 5. Polling Asincrono
                task_info_tree = None
                while True:
                    time.sleep(15)  # Esperar 15s entre pings para no saturar
                    task_info = gmp.get_task(task_id)
                    task_info_tree = etree.fromstring(task_info)
                    
                    status = task_info_tree.xpath('//status/text()')
                    if not status:
                        continue
                    status_text = status[0]
                    
                    progress = task_info_tree.xpath('//progress/text()')
                    progress_text = progress[0] if progress else "0"
                    
                    if progress_text != "-1":
                         logger.info(f"Escaneo GVM - Progreso: {progress_text}% (Estado: {status_text})")
                         
                    if status_text in ['Done', 'Stopped', 'Interrupted', 'Failed']:
                        logger.info(f"Escaneo GVM finalizado. Estado: {status_text}")
                        break
                
                # 6. Parseo de Resultados XML
                logger.info("Obteniendo reporte de vulnerabilidades desde GVM...")
                report_id_nodes = task_info_tree.xpath('//last_report/report/@id')
                if not report_id_nodes:
                    return VulnScanResult(target=target_ip, status=f"terminado ({status_text} sin reporte)", vulnerabilities=[])
                
                report_id = report_id_nodes[0]
                
                # Pedimos el reporte filtrando para que nos devuelva amenazas > 0 (High/Med/Low)
                report_details = gmp.get_report(report_id, details=True, filter_string="apply_overrides=0 levels=hml")
                report_tree = etree.fromstring(report_details)
                
                vulns = []
                for result in report_tree.xpath('//report/report/results/result'):
                    name = result.find('name').text if result.find('name') is not None else "Desconocido"
                    desc = result.find('description').text if result.find('description') is not None else ""
                    
                    cve = "Normal"
                    nvt = result.find('nvt')
                    if nvt is not None:
                        cve_node = nvt.find('cve')
                        if cve_node is not None and cve_node.text != "NOCVE":
                            cve = cve_node.text
                        else:
                            oid_node = nvt.find('oid')
                            if oid_node is not None:
                                cve = f"OID:{oid_node.text}"
                                
                    severity = 0.0
                    sev_node = result.find('severity')
                    if sev_node is not None and sev_node.text != "":
                        try:
                            severity = float(sev_node.text)
                        except ValueError:
                            pass
                            
                    vulns.append(Vulnerability(cve=cve, severity=severity, name=name, description=desc))
                
                logger.info(f"GVM Reporte Final: Se encontraron {len(vulns)} vulnerabilidades.")
                return VulnScanResult(target=target_ip, status="escaneo GVM real completado", vulnerabilities=vulns)

        except (ConnectionRefusedError, socket.timeout, ConnectionResetError) as e:
            logger.error("No se pudo conectar al demonio de GVM. ¿Esta corriendo?")
            return VulnScanResult(target=target_ip, status="fallo (gvm inalcanzable)", vulnerabilities=[])
        except GvmError as e:
            logger.error(f"Error en el protocolo GMP: {e}")
            return VulnScanResult(target=target_ip, status=f"fallo (error gmp: {e})", vulnerabilities=[])
        except Exception as e:
            logger.error(f"Problema fatal durante escaneo GVM: {e}")
            return VulnScanResult(target=target_ip, status="fallo critico", vulnerabilities=[])
