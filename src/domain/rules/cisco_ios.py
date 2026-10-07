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
            description="Verifica que el servicio de encriptación de contraseñas esté habilitado globalmente. Cuando no está habilitado, las contraseñas de las líneas virtuales, consola y enable se almacenan en texto claro en el archivo de configuración, exponiendo gravemente el acceso al equipo en caso de filtración del archivo .cfg (Referencia: DISA STIG Cisco IOS Router).",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("service password-encryption" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "La directiva 'service password-encryption' se encuentra habilitada globalmente.")
        return AuditResult(
            self.rule_definition, False, "ALERTA DE EXPOSICIÓN: La directiva 'service password-encryption' no fue detectada en la configuración. Esto indica que contraseñas locales, cadenas de comunidad SNMP, claves IPsec o llaves BGP pueden estar almacenadas en texto completamente legible. Un atacante que comprometa un acceso de bajo privilegio (Nivel 1) o capture un backup del archivo .cfg podría obtener credenciales de administrador de forma trivial.",
            remediation="""configure terminal
service password-encryption
exit
write memory"""
        )

class SEC02_NoTelnet(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-02",
            name="Inhabilitación del Protocolo Telnet (CWE-319)",
            description="Audita las líneas de terminal virtual (VTY) para garantizar que el protocolo inseguro Telnet esté desactivado y reemplazado exclusivamente por Secure Shell (SSH). Telnet transmite todas las comunicaciones, incluyendo nombres de usuario y contraseñas de administrador, en formato de texto claro a través de la red. Esto permite a cualquier actor malicioso en el mismo segmento de red interceptar credenciales utilizando técnicas de sniffing (como Wireshark o tcpdump). (Referencia: NIST SP 800-48, CVE-1999-0619).",
            severity=Severity.CRITICAL
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("transport input ssh" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "Se verificó que el protocolo SSH está forzado en las líneas VTY, mitigando ataques de intercepción de red (Man-in-the-Middle) y sniffing de credenciales.")
        return AuditResult(
            self.rule_definition, False, "VULNERABILIDAD CRÍTICA: No se detectó 'transport input ssh' en la configuración de las líneas VTY. El dispositivo podría estar aceptando conexiones Telnet (puerto TCP 23). Motores de búsqueda de IoT como Shodan catalogan rutinariamente routers Cisco con Telnet expuesto, convirtiéndolos en blancos inmediatos para botnets (ej. Mirai) y ataques de fuerza bruta remota.",
            remediation="""configure terminal
line vty 0 4
transport input ssh
login local
exit
line vty 5 15
transport input ssh
login local
exit
write memory"""
        )

class SEC03_ExecTimeout(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-03",
            name="Timeout de Sesión Inactiva (CWE-613)",
            description="Verifica que exista un temporizador de inactividad (timeout) configurado tanto para las líneas de Consola física como para las terminales virtuales (VTY). Si una sesión administrativa se deja abierta e inactiva, un atacante físico o lógico podría secuestrar (hijack) la sesión previamente autenticada y realizar cambios destructivos en el equipo sin necesidad de conocer las credenciales de acceso. (Referencia: PCI-DSS Requisito 8.1.8 - Expiración de sesiones inactivas).",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("exec-timeout" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "Las líneas de gestión cuentan con un timeout de inactividad, previniendo el secuestro de sesiones (Session Hijacking).")
        return AuditResult(
            self.rule_definition, False, "RIESGO OPERACIONAL: Las líneas administrativas (Console/VTY) carecen de un temporizador de cierre 'exec-timeout'. Un usuario que olvide cerrar sesión dejará una puerta trasera abierta indefinidamente con privilegios elevados. Se recomienda forzar un cierre automático tras 5 a 10 minutos de inactividad.",
            remediation="""configure terminal
line console 0
exec-timeout 5 0
exit
line vty 0 15
exec-timeout 5 0
exit
write memory"""
        )

class SEC04_NoIPHttpServer(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-04",
            name="Servidor HTTP de Gestión (CVE-2018-0171)",
            description="Inspecciona la presencia del servidor HTTP embebido del IOS ('ip http server'). Cisco provee una interfaz gráfica web para gestión, pero si no está cifrada mediante HTTPS, expone tokens y credenciales de gestión al tráfico de red. Peor aún, históricamente el servidor HTTP del IOS ha estado plagado de vulnerabilidades de desbordamiento de búfer (Buffer Overflow) y ejecución remota de código (RCE), como el famoso CVE-2018-0171 (Smart Install) y vulnerabilidades del WebUI que son indexadas masivamente por Shodan y Censys.",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("no ip http server" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "El servidor HTTP no cifrado de Cisco ha sido deshabilitado correctamente, cerrando un vector histórico de ataques RCE.")
        return AuditResult(
            self.rule_definition, False, "SUPERFICIE DE ATAQUE ACTIVA: No se detectó 'no ip http server'. El dispositivo mantiene habilitado el puerto TCP 80 para la administración WebUI. Además de interceptación de tráfico (Man-in-the-Middle), los escáneres de internet identifican la firma de 'Cisco IOS HTTP Server' y lanzan exploits automatizados de forma continua para vulnerar la memoria del router.",
            remediation="""configure terminal
no ip http server
! Si requieres gestión web, habilita únicamente la versión segura:
ip http secure-server
ip http authentication local
exit
write memory"""
        )

class SEC05_LoggingEnabled(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-05",
            name="Centralización de Logs (CWE-778)",
            description="Audita que el enrutador esté redirigiendo sus registros de eventos (syslog) a un servidor remoto (SIEM) en lugar de depender exclusivamente del buffer de memoria local. Los logs locales son volátiles, se pierden ante un reinicio y, en caso de compromiso total, el atacante puede borrarlos ('clear logging') para eliminar sus huellas (Anti-Forensics). Un sistema seguro debe transmitir logs externamente en tiempo real para detección de intrusos. (Referencia: ISO 27001 - A.12.4.1 Registro de eventos).",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any(line.strip().startswith("logging host") or (line.strip().startswith("logging ") and not line.strip() == "logging buffered") for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "El equipo está configurado para exportar telemetría y eventos de seguridad hacia una IP externa (Syslog/SIEM).")
        return AuditResult(
            self.rule_definition, False, "FALLA DE TRAZABILIDAD: No se ha configurado un servidor Syslog ('logging host'). La carencia de telemetría remota significa que si el router sufre una brecha de seguridad y el atacante borra los registros locales o reinicia el equipo, será virtualmente imposible realizar una investigación forense post-incidente para descubrir cómo entraron.",
            remediation="""configure terminal
! Reemplaza X.X.X.X con la IP de tu servidor Syslog o SIEM
logging host X.X.X.X
logging trap warnings
logging origin-id hostname
exit
write memory"""
        )

def get_all_cisco_rules() -> list[BaseRule]:
    return [
        SEC01_PasswordEncryption(),
        SEC02_NoTelnet(),
        SEC03_ExecTimeout(),
        SEC04_NoIPHttpServer(),
        SEC05_LoggingEnabled()
    ]
