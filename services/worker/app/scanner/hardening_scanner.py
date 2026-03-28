"""
codigo q escanea normas en los sistemas operativos (hardening)
"""

import platform
import subprocess
import logging
from dataclasses import dataclass, field
from typing import List

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger(__name__)

@dataclass
class CISControl:
    control_id: str
    name: str
    status: str          # "pass", "fail", "manual_check"
    severity: str        # "low", "medium", "high", "critical"
    description: str     # Razón o remediación recomendada

@dataclass
class HardeningResult:
    os_detected: str
    os_release: str
    hardening_score: int         # Puntuación global del sistema (0-100)
    controls: List[CISControl] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

class HardeningScanner:
    """revisa las politicas de seguridad dependiendo el os"""

    def __init__(self):
        self.os_name = platform.system()  # "Windows", "Linux", "Darwin"
        self.os_release = platform.release()

    def _check_windows_firewall(self) -> CISControl:
        """Comprueba si el Firewall de Windows está activado usando netsh."""
        control = CISControl(
            control_id="CIS-9.1",
            name="Windows Firewall State",
            status="manual_check",
            severity="high",
            description="Ensure Windows Defender Firewall is turned on for all profiles."
        )
        try:
            # Ejecuta un comando simple para ver el estado de todos los perfiles
            result = subprocess.run(["netsh", "advfirewall", "show", "allprofiles", "state"], 
                                    capture_output=True, text=True, timeout=5)
            
            # Si el comando retorna 'ON' para todos, pasó. Si hay algún 'OFF', falla.
            output_lower = result.stdout.lower()
            if "estado" in output_lower or "state" in output_lower:
                if "off" in output_lower or "inactivo" in output_lower:
                    control.status = "fail"
                    control.description = "El firewall de Windows tiene perfiles apagados/inactivos."
                else:
                    control.status = "pass"
                    control.description = "Todos los perfiles principales del firewall están encendidos."
        except Exception as e:
            control.status = "fail"
            control.description = f"Error ejecutando comprobación netsh: {e}"

        return control

    def _check_windows_uac(self) -> CISControl:
        """Comprueba el estado del User Account Control (UAC) en el registro de Windows."""
        import winreg
        control = CISControl(
            control_id="CIS-2.2.1",
            name="User Account Control (UAC)",
            status="manual_check",
            severity="high",
            description="Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'."
        )
        
        # En Linux no correrá este método, es exclusivo de winreg.
        try:
            # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
            # Valor esperado: EnableLUA = 1
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")
            value, _ = winreg.QueryValueEx(key, "EnableLUA")
            winreg.CloseKey(key)

            if value == 1:
                control.status = "pass"
                control.description = "UAC está habilitado en el sistema (EnableLUA=1)."
            else:
                control.status = "fail"
                control.description = "UAC está deshabilitado. Se recomienda encarecidamente activar EnableLUA."
        except Exception as e:
            control.status = "fail"
            control.description = f"Error leyendo registro para UAC: {e}"
        
        return control

    def _execute_linux_hardening_real(self) -> List[CISControl]:
        """ejecuta el comando en linux y parsea el archivo dat q tira lynis"""
        logger.info("leyendo politicas con lynis (linux)...")
        controls = []
        try:
            subprocess.run(["lynis", "audit", "system", "-Q"], capture_output=True, text=True, timeout=300)
            
            with open("/var/log/lynis-report.dat", "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line in lines:
                if line.startswith("warning[]="):
                    parts = line.split("=", 1)[1].split("|")
                    if len(parts) >= 2:
                        controls.append(CISControl(control_id=parts[0], name="Warning", status="fail", severity="high", description=parts[1].strip()))
                elif line.startswith("suggestion[]="):
                    parts = line.split("=", 1)[1].split("|")
                    if len(parts) >= 2:
                        controls.append(CISControl(control_id=parts[0], name="Suggestion", status="fail", severity="medium", description=parts[1].strip()))
                        
            if not controls:
                controls.append(CISControl("SCAN-01", "Escaneo Exitoso", "pass", "low", "No se detectaron sugerencias o warnings críticos en este container."))
                
        except Exception as e:
            logger.error(f"nos fuimos a la b ejecutando lynis: {e}")
            controls.append(CISControl("ERR-01", "error de lectura", "fail", "high", str(e)))
            
        return controls

    def scan(self) -> HardeningResult:
        """ejecuta todas las reglas correspondientes"""
        logger.info(f"evaluando hardening en OS: {self.os_name} {self.os_release}")
        
        controls = []
        errors = []

        if self.os_name == "Windows":
            try:
                controls.append(self._check_windows_firewall())
                controls.append(self._check_windows_uac())
            except Exception as e:
                errors.append(f"Falla general en Windows Checks: {e}")
        
        elif self.os_name == "Linux" or self.os_name == "Darwin":
            try:
                controls.extend(self._execute_linux_hardening_real())
            except Exception as e:
                errors.append(f"Falla en Unix Checks: {e}")
        
        else:
            errors.append(f"SO no soportado para auto-hardening: {self.os_name}")

        # Calcular score básico (0 - 100) basado en porcentajes de "pass" (ignora los ignore/manual)
        pass_count = sum(1 for c in controls if c.status == "pass")
        fail_count = sum(1 for c in controls if c.status == "fail")
        total_evaluados = pass_count + fail_count
        
        score = 0
        if total_evaluados > 0:
            score = int((pass_count / total_evaluados) * 100)
            
        return HardeningResult(
            os_detected=self.os_name,
            os_release=self.os_release,
            hardening_score=score,
            controls=controls,
            errors=errors
        )
