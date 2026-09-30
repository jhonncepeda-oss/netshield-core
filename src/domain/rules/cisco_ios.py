from src.domain.rules.base import BaseRule
from src.domain.models.audit import Rule, AuditResult, Severity

class SEC01_PasswordEncryption(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-01",
            name="Cifrado Global de Contrase?as (CWE-316)",
            description="Verifica que la directiva 'service password-encryption' est? habilitada en el equipo Cisco. Esta funcionalidad aplica un cifrado nativo (Tipo 7) a todas las credenciales que por defecto se almacenar?an en texto plano en la NVRAM del router. Aunque el algoritmo Tipo 7 es considerado d?bil frente a herramientas de descifrado modernas, su ausencia expone inmediatamente las credenciales frente a t?cnicas pasivas como 'shoulder surfing', lectura no autorizada de backups automatizados, y fugas de datos mediante SNMP. (Referencia: CIS Cisco IOS Benchmark v4.0.0, Secci?n 1.2.1).",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("service password-encryption" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "El cifrado global de contrase?as (Tipo 7) se encuentra activado exitosamente, bloqueando la exposici?n directa de texto plano en el archivo running-config.")
        return AuditResult(
            self.rule_definition, False, "ALERTA DE EXPOSICI?N: La directiva 'service password-encryption' no fue detectada en la configuraci?n. Esto indica que contrase?as locales, cadenas de comunidad SNMP, claves IPsec o llaves BGP pueden estar almacenadas en texto completamente legible. Un atacante que comprometa un acceso de bajo privilegio (Nivel 1) o capture un backup del archivo .cfg podr?a obtener credenciales de administrador de forma trivial.",
            remediation="configure terminal
service password-encryption
exit
write memory"
        )

class SEC02_NoTelnet(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-02",
            name="Inhabilitaci?n del Protocolo Telnet (CWE-319)",
            description="Audita las l?neas de terminal virtual (VTY) para garantizar que el protocolo inseguro Telnet est? desactivado y reemplazado exclusivamente por Secure Shell (SSH). Telnet transmite todas las comunicaciones, incluyendo nombres de usuario y contrase?as de administrador, en formato de texto claro a trav?s de la red. Esto permite a cualquier actor malicioso en el mismo segmento de red interceptar credenciales utilizando t?cnicas de sniffing (como Wireshark o tcpdump). (Referencia: NIST SP 800-48, CVE-1999-0619).",
            severity=Severity.CRITICAL
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("transport input ssh" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "Se verific? que el protocolo SSH est? forzado en las l?neas VTY, mitigando ataques de intercepci?n de red (Man-in-the-Middle) y sniffing de credenciales.")
        return AuditResult(
            self.rule_definition, False, "VULNERABILIDAD CR?TICA: No se detect? 'transport input ssh' en la configuraci?n de las l?neas VTY. El dispositivo podr?a estar aceptando conexiones Telnet (puerto TCP 23). Motores de b?squeda de IoT como Shodan catalogan rutinariamente routers Cisco con Telnet expuesto, convirti?ndolos en blancos inmediatos para botnets (ej. Mirai) y ataques de fuerza bruta remota.",
            remediation="configure terminal
line vty 0 4
transport input ssh
login local
exit
line vty 5 15
transport input ssh
login local
exit
write memory"
        )

class SEC03_ExecTimeout(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-03",
            name="Timeout de Sesi?n Inactiva (CWE-613)",
            description="Verifica que exista un temporizador de inactividad (timeout) configurado tanto para las l?neas de Consola f?sica como para las terminales virtuales (VTY). Si una sesi?n administrativa se deja abierta e inactiva, un atacante f?sico o l?gico podr?a secuestrar (hijack) la sesi?n previamente autenticada y realizar cambios destructivos en el equipo sin necesidad de conocer las credenciales de acceso. (Referencia: PCI-DSS Requisito 8.1.8 - Expiraci?n de sesiones inactivas).",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("exec-timeout" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "Las l?neas de gesti?n cuentan con un timeout de inactividad, previniendo el secuestro de sesiones (Session Hijacking).")
        return AuditResult(
            self.rule_definition, False, "RIESGO OPERACIONAL: Las l?neas administrativas (Console/VTY) carecen de un temporizador de cierre 'exec-timeout'. Un usuario que olvide cerrar sesi?n dejar? una puerta trasera abierta indefinidamente con privilegios elevados. Se recomienda forzar un cierre autom?tico tras 5 a 10 minutos de inactividad.",
            remediation="configure terminal
line console 0
exec-timeout 5 0
exit
line vty 0 15
exec-timeout 5 0
exit
write memory"
        )

class SEC04_NoIPHttpServer(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-04",
            name="Servidor HTTP de Gesti?n (CVE-2018-0171)",
            description="Inspecciona la presencia del servidor HTTP embebido del IOS ('ip http server'). Cisco provee una interfaz gr?fica web para gesti?n, pero si no est? cifrada mediante HTTPS, expone tokens y credenciales de gesti?n al tr?fico de red. Peor a?n, hist?ricamente el servidor HTTP del IOS ha estado plagado de vulnerabilidades de desbordamiento de b?fer (Buffer Overflow) y ejecuci?n remota de c?digo (RCE), como el famoso CVE-2018-0171 (Smart Install) y vulnerabilidades del WebUI que son indexadas masivamente por Shodan y Censys.",
            severity=Severity.HIGH
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any("no ip http server" in line for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "El servidor HTTP no cifrado de Cisco ha sido deshabilitado correctamente, cerrando un vector hist?rico de ataques RCE.")
        return AuditResult(
            self.rule_definition, False, "SUPERFICIE DE ATAQUE ACTIVA: No se detect? 'no ip http server'. El dispositivo mantiene habilitado el puerto TCP 80 para la administraci?n WebUI. Adem?s de interceptaci?n de tr?fico (Man-in-the-Middle), los esc?neres de internet identifican la firma de 'Cisco IOS HTTP Server' y lanzan exploits automatizados de forma continua para vulnerar la memoria del router.",
            remediation="configure terminal
no ip http server
! Si requieres gesti?n web, habilita ?nicamente la versi?n segura:
ip http secure-server
ip http authentication local
exit
write memory"
        )

class SEC05_LoggingEnabled(BaseRule):
    @property
    def rule_definition(self) -> Rule:
        return Rule(
            rule_id="SEC-05",
            name="Centralizaci?n de Logs (CWE-778)",
            description="Audita que el enrutador est? redirigiendo sus registros de eventos (syslog) a un servidor remoto (SIEM) en lugar de depender exclusivamente del buffer de memoria local. Los logs locales son vol?tiles, se pierden ante un reinicio y, en caso de compromiso total, el atacante puede borrarlos ('clear logging') para eliminar sus huellas (Anti-Forensics). Un sistema seguro debe transmitir logs externamente en tiempo real para detecci?n de intrusos. (Referencia: ISO 27001 - A.12.4.1 Registro de eventos).",
            severity=Severity.MEDIUM
        )

    def evaluate(self, config_lines: list[str]) -> AuditResult:
        passed = any(line.strip().startswith("logging host") or (line.strip().startswith("logging ") and not line.strip() == "logging buffered") for line in config_lines)
        if passed:
            return AuditResult(self.rule_definition, True, "El equipo est? configurado para exportar telemetr?a y eventos de seguridad hacia una IP externa (Syslog/SIEM).")
        return AuditResult(
            self.rule_definition, False, "FALLA DE TRAZABILIDAD: No se ha configurado un servidor Syslog ('logging host'). La carencia de telemetr?a remota significa que si el router sufre una brecha de seguridad y el atacante borra los registros locales o reinicia el equipo, ser? virtualmente imposible realizar una investigaci?n forense post-incidente para descubrir c?mo entraron.",
            remediation="configure terminal
! Reemplaza X.X.X.X con la IP de tu servidor Syslog o SIEM
logging host X.X.X.X
logging trap warnings
logging origin-id hostname
exit
write memory"
        )

def get_all_cisco_rules() -> list[BaseRule]:
    return [
        SEC01_PasswordEncryption(),
        SEC02_NoTelnet(),
        SEC03_ExecTimeout(),
        SEC04_NoIPHttpServer(),
        SEC05_LoggingEnabled()
    ]
