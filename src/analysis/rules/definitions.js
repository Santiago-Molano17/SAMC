/**
 * Reglas de detección de SACM (estilo YARA).
 *
 * - patterns: textos o expresiones regulares que se buscan en el archivo
 * - min: cuántos patrones distintos deben aparecer para que la regla dispare
 * - targets: categorías de archivo a las que aplica (por defecto, todas)
 * - techniques: técnicas MITRE ATT&CK asociadas
 */

// La cadena EICAR se arma por partes para que los antivirus no marquen este código fuente
const EICAR = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*"].join("");

module.exports = [
    {
        id: "eicar_test_file",
        name: "Archivo de prueba EICAR",
        description: "Archivo estándar e inofensivo que los antivirus usan para verificar su funcionamiento.",
        severity: "critical",
        category: "test",
        family: "EICAR-Test-File",
        techniques: [],
        patterns: [EICAR]
    },
    {
        id: "pe_process_injection",
        name: "Inyección de código en otros procesos",
        description: "Usa APIs para reservar memoria y crear hilos dentro de otro proceso, técnica típica de troyanos y loaders.",
        severity: "high",
        category: "injection",
        family: "Trojan.Injector",
        techniques: ["T1055"],
        targets: ["executable", "binary"],
        min: 3,
        patterns: ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "NtWriteVirtualMemory", "RtlCreateUserThread"]
    },
    {
        id: "keylogger_behavior",
        name: "Captura de teclado (keylogger)",
        description: "Instala hooks de teclado o consulta el estado de las teclas para registrar lo que escribe el usuario.",
        severity: "high",
        category: "spyware",
        family: "Spyware.Keylogger",
        techniques: ["T1056.001"],
        min: 2,
        patterns: ["SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState", "GetForegroundWindow", /\bkeylog/i, "WH_KEYBOARD_LL"]
    },
    {
        id: "anti_debugging",
        name: "Evasión de depuradores",
        description: "Comprueba si está siendo analizado para cambiar su comportamiento.",
        severity: "low",
        category: "evasion",
        techniques: ["T1622"],
        targets: ["executable", "binary"],
        min: 3,
        patterns: ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "ZwQueryInformationProcess", "NtSetInformationThread", "OutputDebugString"]
    },
    {
        id: "downloader",
        name: "Descarga de archivos desde internet",
        description: "Contiene funciones o comandos para descargar y ejecutar contenido remoto (dropper / downloader).",
        severity: "medium",
        category: "downloader",
        family: "Trojan.Downloader",
        techniques: ["T1105"],
        patterns: ["URLDownloadToFile", "InternetOpenUrl", "WinHttpOpenRequest", /DownloadString\s*\(/i, /DownloadFile\s*\(/i, /Invoke-WebRequest|\biwr\s+-?u/i, /certutil(\.exe)?\s+-urlcache/i, /bitsadmin(\.exe)?\s+\/transfer/i, /Start-BitsTransfer/i]
    },
    {
        id: "powershell_obfuscation",
        name: "PowerShell ofuscado u oculto",
        description: "Ejecuta PowerShell con comandos codificados, ventana oculta o evaluación dinámica de código.",
        severity: "high",
        category: "script",
        techniques: ["T1059.001", "T1027"],
        min: 2,
        patterns: [/-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}/i, /FromBase64String/i, /\bIEX\b|Invoke-Expression/i, /-w(indowstyle)?\s+hidden/i, /-nop(rofile)?\b/i, /-exec(utionpolicy)?\s+bypass/i, /\[char\]\s*\d+\s*\+/i]
    },
    {
        id: "registry_run_persistence",
        name: "Persistencia en el registro de inicio",
        description: "Se registra en las claves Run/RunOnce o Winlogon para ejecutarse en cada inicio de Windows.",
        severity: "high",
        category: "persistence",
        techniques: ["T1547.001"],
        patterns: [/CurrentVersion\\Run(Once)?\b/i, /Winlogon\\(Shell|Userinit)/i, /\\Start Menu\\Programs\\Startup/i]
    },
    {
        id: "scheduled_task_persistence",
        name: "Persistencia mediante tareas programadas",
        description: "Crea tareas programadas para mantenerse en el sistema.",
        severity: "medium",
        category: "persistence",
        techniques: ["T1053.005"],
        patterns: [/schtasks(\.exe)?\s+\/create/i, /Register-ScheduledTask/i, /New-ScheduledTaskAction/i]
    },
    {
        id: "ransomware_impact",
        name: "Destrucción de copias de seguridad (ransomware)",
        description: "Borra las instantáneas de volumen o desactiva la recuperación de Windows, paso previo al cifrado.",
        severity: "critical",
        category: "ransomware",
        family: "Ransomware.Generic",
        techniques: ["T1490", "T1486"],
        patterns: [/vssadmin(\.exe)?\s+delete\s+shadows/i, /wbadmin\s+delete\s+catalog/i, /bcdedit.{0,20}recoveryenabled\s+no/i, /wmic(\.exe)?\s+shadowcopy\s+delete/i, /Win32_ShadowCopy.{0,40}Delete/i]
    },
    {
        id: "ransomware_note",
        name: "Nota de rescate / cifrado de archivos",
        description: "Menciona cifrado de archivos, pagos en criptomonedas y descifrado, típico de una nota de rescate.",
        severity: "high",
        category: "ransomware",
        family: "Ransomware.Generic",
        techniques: ["T1486"],
        min: 3,
        patterns: [/your files (have been|are) encrypted/i, /\bransom/i, /\bdecrypt(or|ion)?\b/i, /\bbitcoin\b|\bBTC\b/, "CryptEncrypt", /\.onion\b/i, /file_encryption|encrypt(ed)? files/i]
    },
    {
        id: "credential_theft",
        name: "Robo de credenciales",
        description: "Busca contraseñas en la memoria de Windows (LSASS) o en los navegadores.",
        severity: "high",
        category: "stealer",
        family: "Stealer.Generic",
        techniques: ["T1003", "T1555.003"],
        min: 2,
        patterns: [/mimikatz/i, /sekurlsa/i, /\blsass(\.exe)?\b/i, /\\Google\\Chrome\\User Data/i, /Login Data/, /\\Mozilla\\Firefox\\Profiles/i, /logins\.json/i, /wallet\.dat/i]
    },
    {
        id: "spyware_collection",
        name: "Recolección y exfiltración de información",
        description: "Captura pantalla o información del usuario y la envía a un servidor remoto.",
        severity: "high",
        category: "spyware",
        family: "Spyware.Generic",
        techniques: ["T1113", "T1041"],
        min: 2,
        patterns: [/screen\s*(shot|capture)|capture\s+screen|BitBlt/i, /exfiltrat/i, /\bkeylog/i, /upload.{0,20}(server|c2)|remote server/i, /clipboard/i]
    },
    {
        id: "worm_propagation",
        name: "Propagación tipo gusano",
        description: "Intenta replicarse en carpetas compartidas, unidades USB o por la red.",
        severity: "high",
        category: "worm",
        family: "Worm.Generic",
        techniques: ["T1080", "T1091", "T1046"],
        min: 2,
        patterns: [/\breplicat/i, /\bspread\b|propagat/i, /network\s+scan|port\s*scan/i, /shared\s+folders?|\\\\[A-Za-z0-9_-]+\\[A-Za-z$]+/i, /autorun\.inf/i, /removable|\bUSB\b/i]
    },
    {
        id: "office_macro",
        name: "Documento de Office con macros",
        description: "El documento contiene macros VBA, el vector más común de malware por correo.",
        severity: "medium",
        category: "document",
        techniques: ["T1204.002"],
        targets: ["document"],
        when: (ctx) => ctx.fileInfo.hasMacros,
        patterns: []
    },
    {
        id: "office_macro_autoexec",
        name: "Macro que se ejecuta sola al abrir",
        description: "La macro se ejecuta automáticamente al abrir el documento y lanza comandos del sistema.",
        severity: "high",
        category: "document",
        family: "Downloader.Macro",
        techniques: ["T1059.005", "T1204.002"],
        targets: ["document", "script", "text"],
        min: 2,
        patterns: [/\bAuto_?Open\b|\bDocument_Open\b|\bWorkbook_Open\b/i, /\bShell\s*\(/i, /WScript\.Shell/i, /CreateObject\s*\(/i, /\bEnviron\s*\(/i]
    },
    {
        id: "pdf_active_content",
        name: "PDF con contenido activo",
        description: "El PDF incluye JavaScript, acciones automáticas o archivos incrustados.",
        severity: "high",
        category: "document",
        techniques: ["T1204.002", "T1059.007"],
        targets: ["document"],
        min: 2,
        patterns: [/\/JavaScript\b/, /\/JS\b/, /\/OpenAction\b/, /\/Launch\b/, /\/EmbeddedFile\b/, /\/AA\b/]
    },
    {
        id: "windows_script_host",
        name: "Ejecución con Windows Script Host",
        description: "Scripts VBS/JS que crean objetos del sistema para ejecutar comandos.",
        severity: "medium",
        category: "script",
        techniques: ["T1059.005", "T1059.007"],
        min: 2,
        patterns: [/WScript\.Shell/i, /Shell\.Application/i, /ActiveXObject/i, /\.Run\s*\(/i, /Scripting\.FileSystemObject/i, /ADODB\.Stream/i]
    },
    {
        id: "script_obfuscation",
        name: "Código ofuscado",
        description: "Usa codificación o evaluación dinámica para ocultar su lógica real.",
        severity: "medium",
        category: "evasion",
        techniques: ["T1027"],
        targets: ["script", "text", "document"],
        min: 2,
        patterns: [/eval\s*\(\s*(atob|unescape|String\.fromCharCode)/i, /(String\.fromCharCode\s*\([^)]*\)\s*\+?\s*){3,}/i, /(\\x[0-9a-f]{2}){20,}/i, /[A-Za-z0-9+/]{400,}={0,2}/, /\bunescape\s*\(/i, /\bchr\s*\(\s*\d+\s*\)\s*&/i]
    },
    {
        id: "lolbins",
        name: "Abuso de binarios legítimos de Windows",
        description: "Usa herramientas propias de Windows (mshta, rundll32, regsvr32...) para ejecutar código malicioso.",
        severity: "medium",
        category: "evasion",
        techniques: ["T1218"],
        patterns: [/mshta(\.exe)?\s+(http|vbscript|javascript)/i, /regsvr32(\.exe)?\s+\/s\s+\/(n|u|i)/i, /rundll32(\.exe)?\s+\S+,\s*\w+/i, /wmic(\.exe)?\s+process\s+call\s+create/i, /certutil(\.exe)?\s+-decode/i, /InstallUtil(\.exe)?/i]
    },
    {
        id: "disable_security_tools",
        name: "Desactivación de defensas",
        description: "Intenta apagar el antivirus, el firewall o la protección en tiempo real.",
        severity: "high",
        category: "evasion",
        techniques: ["T1562.001"],
        patterns: [/Set-MpPreference\s+-Disable/i, /DisableAntiSpyware/i, /DisableRealtimeMonitoring/i, /netsh\s+advfirewall\s+set\s+\w+\s+state\s+off/i, /Add-MpPreference\s+-ExclusionPath/i]
    },
    {
        id: "system_discovery",
        name: "Reconocimiento del sistema",
        description: "Recopila información del equipo, usuarios y red.",
        severity: "low",
        category: "discovery",
        techniques: ["T1082", "T1087"],
        min: 3,
        patterns: [/\bwhoami\b/i, /\bsysteminfo\b/i, /ipconfig\s+\/all/i, /net\s+user\b/i, /net\s+group\s+"?domain admins/i, /\btasklist\b/i, /\bnetstat\s+-an/i, /Get-ComputerInfo/i]
    },
    {
        id: "c2_web_services",
        name: "Comunicación con servicios web de terceros",
        description: "Usa Telegram, Discord, Pastebin u otros servicios como canal de control o de robo de datos.",
        severity: "medium",
        category: "c2",
        techniques: ["T1102", "T1071.001"],
        patterns: [/api\.telegram\.org\/bot/i, /discord(app)?\.com\/api\/webhooks/i, /pastebin\.com\/raw/i, /ngrok\.io|ngrok-free\.app/i, /transfer\.sh/i]
    },
    {
        id: "packer_upx",
        name: "Ejecutable empaquetado",
        description: "El ejecutable está comprimido con un empaquetador, lo que dificulta su análisis.",
        severity: "medium",
        category: "packer",
        techniques: ["T1027.002"],
        targets: ["executable"],
        patterns: ["UPX!", /\bUPX[01]\b/, ".aspack", ".themida", ".vmp0", "MPRESS1"]
    },
    {
        id: "crypto_miner",
        name: "Minero de criptomonedas",
        description: "Contiene configuraciones de minería que consumen los recursos del equipo.",
        severity: "high",
        category: "miner",
        family: "Miner.XMRig",
        techniques: ["T1496"],
        patterns: [/stratum\+(tcp|ssl):\/\//i, /\bxmrig\b/i, /cryptonight/i, /--donate-level/i, /monero(ocean)?/i]
    },
    {
        id: "reverse_shell",
        name: "Shell inversa",
        description: "Abre una consola remota hacia el atacante.",
        severity: "high",
        category: "backdoor",
        family: "Backdoor.ReverseShell",
        techniques: ["T1059.004"],
        patterns: [/bash\s+-i\s+>&\s*\/dev\/tcp\//i, /\bnc(at)?\s+(-e|-c)\s+\/bin\/(ba)?sh/i, /\/bin\/sh\s+-i/i, /pty\.spawn\s*\(/i, /socket\.socket\(.{0,80}subprocess/is]
    }
];
