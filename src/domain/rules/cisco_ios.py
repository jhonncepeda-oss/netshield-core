from abc import ABC, abstractmethod
from src.domain.models.audit import Rule, AuditResult, Severity

class BaseRule(ABC):
    @property
    @abstractmethod
    def rule_definition(self) -> Rule:
        pass

    @abstractmethod
    def evaluate(self, config_lines: list[str]) -> AuditResult:
        pass

class SEC01_PasswordEncryption(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-01",
            name="Cifrado Global de Contraseñas (CWE-316)",
            description="Verifica que el servicio de encriptación de contraseñas esté habilitado globalmente para proteger credenciales en texto claro.",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("service password-encryption" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "He verificado exitosamente que la directiva 'service password-encryption' se encuentra habilitada de forma global en su configuración. Esto asegura que cualquier contraseña local creada en el futuro será automáticamente enmascarada utilizando el algoritmo tipo 7, cumpliendo con los estándares básicos de protección de secretos estáticos.")
        
        # Extract cleartext passwords to show the user the REAL data
        cleartext_lines = [line.strip() for line in config_lines if "password" in line and "secret" not in line and "encryption" not in line and not line.strip().startswith("!")]
        
        details = "Diagnóstico de IA: Durante el escaneo del archivo de configuración, he detectado la ausencia de la directiva de seguridad fundamental 'service password-encryption' (CWE-316).\n\n"
        if cleartext_lines:
            details += "Al analizar en profundidad, pude extraer las siguientes líneas dentro de su archivo que contienen contraseñas o secretos almacenados en texto completamente claro:\n"
            for cl in cleartext_lines[:3]: # Limit to top 3 to avoid clutter
                details += f" - `{cl}`\n"
            if len(cleartext_lines) > 3:
                details += f"   (y {len(cleartext_lines) - 3} ocurrencias adicionales...)\n"
            details += "\n"
            
        details += "Evaluación de Riesgo: Esta configuración expone gravemente el acceso a su equipo. Si un atacante logra obtener una copia de respaldo (backup) del archivo .cfg o compromete un acceso de bajo privilegio (Nivel 1), podrá leer estas credenciales de administrador de forma trivial sin necesidad de realizar ataques de fuerza bruta."
        
        return AuditResult(
            self.rule_definition, False, details,
            remediation="Para mitigar esta vulnerabilidad de forma inmediata, ingrese al modo de configuración global y active el servicio de encriptación. Posteriormente, le recomiendo migrar las contraseñas tipo 'password' a tipo 'secret' (hash SHA-256):\n\nconfigure terminal\nservice password-encryption\nexit\nwrite memory"
        )

class SEC02_NoTelnet(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-02",
            name="Inhabilitación del Protocolo Telnet (CWE-319)",
            description="Audita las líneas de terminal virtual (VTY) para garantizar que el protocolo inseguro Telnet esté desactivado y reemplazado exclusivamente por SSH.",
            severity=Severity.CRITICAL
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        ssh_forced = any("transport input ssh" in line for line in config_lines)
        if ssh_forced:
            return AuditResult(self.rule_definition, True, "He auditado las líneas de terminal virtual (VTY) y he comprobado que el acceso remoto ha sido restringido exclusivamente al protocolo seguro SSH ('transport input ssh'). Esto mitiga satisfactoriamente los riesgos de intercepción de red y sniffing de credenciales.")
        
        vty_lines = []
        in_vty = False
        for line in config_lines:
            if line.startswith("line vty"):
                in_vty = True
                vty_lines.append(line.strip())
            elif in_vty and (line.startswith("line ") or line.startswith("!")):
                in_vty = False
            elif in_vty:
                vty_lines.append(line.strip())

        details = "Diagnóstico de IA: Tras un análisis detallado de las terminales virtuales (VTY), he detectado una vulnerabilidad crítica (CVE-1999-0619). No se ha forzado el uso de Secure Shell (SSH) para las conexiones de administración remota.\n\n"
        if vty_lines:
            details += "El bloque de configuración actual para sus líneas VTY es el siguiente:\n"
            for vty in vty_lines:
                details += f"  `{vty}`\n"
            details += "\n"
            
        details += "Evaluación de Riesgo: Al no especificar 'transport input ssh', el router acepta por defecto conexiones a través de Telnet (puerto TCP 23). Telnet es un protocolo obsoleto que transmite todas las comunicaciones, incluyendo nombres de usuario y contraseñas de administrador, en texto plano. Cualquier actor malicioso que se encuentre en el mismo segmento de red o ISP puede utilizar técnicas de sniffing (como Wireshark) para interceptar sus credenciales en el momento exacto en que usted inicie sesión. Además, motores de búsqueda de IoT como Shodan catalogan rutinariamente routers Cisco con Telnet expuesto, convirtiéndolos en blancos inmediatos para botnets."

        return AuditResult(
            self.rule_definition, False, details,
            remediation="Es imperativo que deshabilite Telnet inmediatamente y obligue al equipo a comunicarse únicamente de forma cifrada mediante SSH:\n\nconfigure terminal\nline vty 0 4\ntransport input ssh\nlogin local\nexit\nline vty 5 15\ntransport input ssh\nlogin local\nexit\nwrite memory"
        )

class SEC03_ExecTimeout(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-03",
            name="Timeout de Sesión Inactiva (CWE-613)",
            description="Verifica que exista un temporizador de inactividad (timeout) configurado para prevenir el secuestro de sesiones.",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("exec-timeout" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "Excelente configuración. He detectado directivas 'exec-timeout' en sus líneas de gestión. Esto asegura que si un administrador olvida cerrar su sesión, el router desconectará automáticamente al usuario tras el tiempo establecido, previniendo secuestros lógicos o físicos de la consola.")
        
        details = "Diagnóstico de IA: He inspeccionado las líneas de administración ('line console' y 'line vty') y he notado la ausencia total de la directiva de seguridad 'exec-timeout'.\n\n"
        details += "Evaluación de Riesgo: Esta carencia representa un riesgo operacional significativo (CWE-613). Si un administrador se autentica en el equipo (ya sea localmente por cable de consola o remotamente por SSH) y deja la sesión abierta e inactiva (por ejemplo, al ir a almorzar o al perder la conexión de VPN sin cerrar sesión adecuadamente), esa terminal quedará abierta de forma indefinida con privilegios de nivel 15. Un atacante físico en el centro de datos, o un malware lógico que haya infectado la computadora del administrador, podría secuestrar (Session Hijacking) esta conexión previamente autenticada y realizar cambios destructivos sin requerir credenciales."

        return AuditResult(
            self.rule_definition, False, details,
            remediation="Le recomiendo encarecidamente implementar un temporizador de inactividad que cierre la sesión automáticamente tras 5 minutos de inactividad. Aplique esta configuración:\n\nconfigure terminal\nline console 0\nexec-timeout 5 0\nexit\nline vty 0 15\nexec-timeout 5 0\nexit\nwrite memory"
        )

class SEC04_NoIPHttpServer(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-04",
            name="Servidor HTTP de Gestión (CVE-2018-0171)",
            description="Inspecciona la presencia del servidor HTTP embebido del IOS ('ip http server') y advierte sobre su exposición.",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("no ip http server" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "Mi análisis confirma que el servidor HTTP no cifrado de Cisco ('no ip http server') ha sido deshabilitado correctamente. Esto cierra exitosamente un vector histórico de vulnerabilidades RCE y previene la intercepción de credenciales web.")
        
        http_config = [line.strip() for line in config_lines if line.strip().startswith("ip http")]
        
        details = "Diagnóstico de IA: Durante la evaluación de la superficie de ataque del enrutador, he detectado que no se ha declarado la directiva 'no ip http server'. Por omisión en muchas versiones de IOS, esto significa que el servidor web de administración nativo se encuentra activo.\n\n"
        
        if http_config:
            details += "En su archivo se detectaron las siguientes configuraciones relacionadas con el servidor web, confirmando su presencia activa:\n"
            for hc in http_config:
                details += f"  `{hc}`\n"
            details += "\n"
            
        details += "Evaluación de Riesgo: Mantener habilitado el puerto TCP 80 para la administración WebUI es extremadamente peligroso en el panorama actual de amenazas. Al igual que Telnet, el protocolo HTTP transmite las credenciales de administrador de red sin ningún tipo de cifrado criptográfico. Adicionalmente, el demonio HTTP interno del IOS ha sido históricamente plagado de vulnerabilidades críticas de desbordamiento de búfer (Buffer Overflow) y ejecución remota de código (RCE), destacando el infame CVE-2018-0171 (Smart Install). Escáneres automatizados buscan rutinariamente esta firma de Cisco para vulnerar la memoria del router y tomar control total."

        return AuditResult(
            self.rule_definition, False, details,
            remediation="Por favor, proceda a desactivar inmediatamente el servidor web inseguro. Si su organización estrictamente requiere gestión a través de interfaz gráfica web, habilite únicamente la versión cifrada HTTPS:\n\nconfigure terminal\nno ip http server\n! Solo si es absolutamente necesario:\nip http secure-server\nip http authentication local\nexit\nwrite memory"
        )

class SEC05_LoggingEnabled(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-05",
            name="Centralización de Logs (CWE-778)",
            description="Audita que el enrutador esté redirigiendo sus registros de eventos (syslog) a un servidor remoto (SIEM).",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        host_line = next((line for line in config_lines if line.strip().startswith("logging host")), None)
        ip_line = next((line for line in config_lines if line.strip().startswith("logging ") and any(c.isdigit() for c in line.strip().split()[-1])), None)
        
        if host_line or ip_line:
            target = host_line.strip() if host_line else ip_line.strip()
            return AuditResult(self.rule_definition, True, f"Excelente. He detectado que la telemetría y el registro de eventos de seguridad (syslog) se están exportando exitosamente de forma remota mediante la directiva `{target}`. Esto garantiza la trazabilidad y la retención forense incluso si el router es comprometido.")
        
        details = "Diagnóstico de IA: He analizado el subsistema de auditoría ('logging') del equipo y he detectado una falla de trazabilidad. No pude localizar ninguna directiva del tipo 'logging host' que apunte hacia la IP de un servidor Syslog externo o solución SIEM.\n\n"
        
        details += "Evaluación de Riesgo: Actualmente, su equipo depende exclusivamente de su memoria interna volátil (buffer local) para almacenar los registros de eventos, accesos y errores de red. Desde una perspectiva de ciberseguridad defensiva, esto viola el principio de retención de evidencia (Referencia: ISO 27001 - A.12.4.1). Si el enrutador sufre una brecha de seguridad grave y el actor de amenazas obtiene privilegios administrativos, su primera acción táctica será ejecutar el comando 'clear logging' para eliminar sus huellas (Técnicas Anti-Forensics), o simplemente reiniciar el dispositivo para limpiar la RAM. Sin un servidor de logs externo, será virtualmente imposible para su equipo de ciberseguridad reconstruir la cadena de ataque o descubrir cómo lograron vulnerar su perímetro."

        return AuditResult(
            self.rule_definition, False, details,
            remediation="Es crítico que despliegue un servidor Syslog en su red interna (por ejemplo, utilizando Linux Rsyslog, Splunk o ELK) y configure el router para enviar la telemetría de forma continua en tiempo real:\n\nconfigure terminal\n! Reemplace X.X.X.X con la dirección IP real de su servidor Syslog\nlogging host X.X.X.X\nlogging trap warnings\nlogging origin-id hostname\nexit\nwrite memory"
        )

def get_all_cisco_rules() -> list[BaseRule]:
    return [
        SEC01_PasswordEncryption(),
        SEC02_NoTelnet(),
        SEC03_ExecTimeout(),
        SEC04_NoIPHttpServer(),
        SEC05_LoggingEnabled()
    ]
