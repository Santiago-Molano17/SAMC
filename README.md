# 🛡️ SACM: Sistema de Análisis y Control de Malware

Plataforma web para **analizar archivos sospechosos sin ejecutarlos**. Combina análisis estático propio, reglas de comportamiento mapeadas a **MITRE ATT&CK** e inteligencia de amenazas de **VirusTotal, MalwareBazaar, URLhaus y CIRCL**. El resultado es un veredicto con un puntaje de riesgo **explicable**: cada punto indica de dónde viene.

Incluye un centro de trabajo para analistas (cola de revisión, analítica de tendencias, casos de investigación y explorador de IOC), gestión de usuarios con 4 roles y auditoría completa.

> Proyecto académico de Fundamentos de Seguridad Informática, construido siguiendo buenas prácticas de OWASP.

<!-- Agrega aquí tus capturas, por ejemplo:
![Panel del analista](docs/capturas/panel.png)
![Reporte de análisis](docs/capturas/reporte.png)
![Analítica](docs/capturas/analitica.png)
-->

## ✨ Qué hace

### Motor de análisis
| Capa | Qué revisa |
|---|---|
| **Identificación real** | Detecta el tipo por sus *bytes mágicos* (PE, ELF, Mach-O, PDF, Office, ZIP, APK, scripts…), no por la extensión. Encuentra ejecutables disfrazados, doble extensión (`factura.pdf.exe`) y el truco del carácter RTLO. |
| **Análisis estático** | MD5/SHA-1/SHA-256, entropía de Shannon (global y por bloques), macros VBA, cabeceras PE (arquitectura, secciones W+X, empaquetadores como UPX, importaciones y *overlay*). |
| **Cadenas e IOC** | Extrae cadenas ASCII/UTF-16 y de ellas URLs, dominios, IP, correos, claves de registro, rutas y billeteras, filtrando dominios legítimos. |
| **25 reglas + MITRE ATT&CK** | Inyección de procesos, keyloggers, ransomware, robo de credenciales, persistencia, PowerShell ofuscado, macros, PDF con JavaScript, binarios LOLBins, mineros y más. Cada regla está vinculada a técnicas de ATT&CK. |
| **Inteligencia externa** | **VirusTotal** (70+ antivirus), **MalwareBazaar** (malware confirmado), **URLhaus** (reputación de los dominios/IP del archivo) y **CIRCL hashlookup** (software legítimo conocido, NSRL). Se consulta con el *hash*; el contenido no sale del servidor. |
| **Puntaje explicable** | Combina todas las señales: suma puntos por reglas, fija mínimos por evidencia fuerte (por ejemplo, 10 antivirus lo detectan → ≥92) y **resta** cuando el archivo es software legítimo conocido. Calcula también la confianza según cuántas fuentes respondieron. |

Los análisis corren **en segundo plano** (cola con concurrencia limitada) y la interfaz muestra el progreso en tiempo real. Las muestras se guardan **neutralizadas** (XOR) para que nadie pueda ejecutarlas por accidente.

### Por rol
| Rol | Puede |
|---|---|
| **Usuario** | Subir archivos, ver sus análisis y reportes, editar su perfil y foto. |
| **Analista** | Todo lo anterior, más: **cola de revisión** (confirmar o corregir veredictos), **analítica** (evolución diaria, familias, tácticas ATT&CK en radar, histograma de riesgo, mapa de calor día/hora, desempeño de motores, falsos positivos/negativos, exportación CSV y gráficas en PNG), **casos de investigación** (tablero kanban, bitácora, responsables) y **explorador de IOC** (pivotar entre muestras que comparten dominios o IP). |
| **Administrador** | Gestionar usuarios y analistas, ver la **auditoría** y el estado del **sistema**. |
| **Super administrador** | Todo, incluidos otros administradores y la prueba de las integraciones. |

Cada usuario ve arriba a la izquierda su **foto, nombre y rol**, y tiene su sección **Mi perfil** para editar datos, cambiar la contraseña y subir su foto.

## 🔐 Seguridad implementada

| Control | Implementación |
|---|---|
| Sesión | JWT en **cookie httpOnly + SameSite=Strict** (JavaScript nunca ve el token). Se invalida al cambiar la contraseña o suspender la cuenta. |
| Contraseñas | **bcrypt** (12 rondas), política de complejidad y comparación en tiempo constante aunque el correo no exista. |
| Fuerza bruta | Bloqueo de la cuenta 15 min tras 5 intentos y *rate limiting* por IP en login, registro, API y subidas. |
| Autorización | **RBAC** jerárquico en cada ruta; un admin no puede gestionar admins y siempre queda al menos un super admin. |
| IDOR | Un usuario solo accede a sus análisis; los demás reciben 404 (no se revela que existen). |
| XSS | Plantillas que **escapan todo por defecto** + **CSP estricta** (`script-src 'self'`, sin scripts en línea ni CDNs). |
| Inyección SQL | Consultas parametrizadas en todo el código. |
| Validación | Esquemas **zod** para cuerpo, parámetros y consultas. |
| Archivos | Límite de tamaño, nombre saneado, almacenamiento por hash y fotos validadas por contenido real (no por extensión). |
| CSV | Protección contra inyección de fórmulas al abrir en Excel. |
| Cabeceras | `helmet` (CSP, HSTS en producción, `nosniff`, `frame-ancestors 'none'`…). |
| Auditoría | Registro de logins (exitosos y fallidos), cambios de rol, revisiones, casos y exportaciones con IP y navegador. |
| Errores | Los mensajes internos nunca llegan al cliente. |

## 🧱 Arquitectura

```
SACM/
├── src/                        # Backend (Node.js + Express 5)
│   ├── app.js / server.js      # Aplicación, CSP y arranque
│   ├── config/                 # Variables de entorno validadas y pool MySQL
│   ├── middleware/             # Autenticación, roles, validación, límites y errores
│   ├── modules/                # Un módulo por dominio: rutas + servicio
│   │   ├── auth/  profile/  users/  audit/  system/
│   │   ├── analyses/           # Envíos, reportes, revisiones y panel
│   │   ├── analytics/          # Tendencias, IOC y exportación CSV
│   │   └── cases/              # Casos de investigación
│   ├── analysis/               # Motor de análisis (independiente de la base de datos)
│   │   ├── static/             # Hashes, entropía, tipo real, cadenas/IOC, lector PE
│   │   ├── rules/              # 25 reglas + mapeo MITRE ATT&CK
│   │   ├── providers/          # VirusTotal, MalwareBazaar, URLhaus, CIRCL
│   │   ├── scoring.js          # Puntaje explicable
│   │   ├── pipeline.js         # Ejecuta y guarda un análisis
│   │   └── queue.js            # Cola en segundo plano
│   └── utils/
├── public/                     # Frontend (HTML + CSS + JavaScript con módulos ES)
│   ├── index.html  login.html  register.html  app.html
│   └── assets/
│       ├── css/                # tokens, base, componentes, layout, páginas, animaciones
│       └── js/
│           ├── core/           # API, sesión, enrutador, plantillas seguras, formatos
│           ├── ui/             # Iconos, gráficas, modales, toasts, componentes
│           ├── layout/         # Barra lateral y superior
│           └── pages/          # Una vista por sección
├── database/migrations/        # Esquema versionado y datos de referencia
├── scripts/                    # Migrar, datos demo, importar v1, crear usuario, etc.
├── samples/                    # Muestras de prueba INOFENSIVAS
└── tests/                      # Pruebas del motor (node:test)
```

### Base de datos (MySQL 8, normalizada)
`roles` · `users` · `user_profiles` · `samples` (un registro por SHA-256) · `analyses` · `engine_results` (resultado de cada motor) · `indicators` (IOC) · `rule_matches` · `mitre_techniques` · `analysis_techniques` · `analysis_reviews` · `cases` · `case_analyses` · `case_notes` · `audit_logs` · `schema_migrations`.

## 🚀 Cómo ejecutarlo

**Requisitos:** Node.js 20 o superior y MySQL 8.

1. Instala las dependencias:
   ```bash
   npm install
   ```
2. Copia `.env.example` como `.env` y completa los datos de MySQL y un `JWT_SECRET`.
3. Crea la base de datos con usuarios y datos de demostración:
   ```bash
   npm run db:setup
   ```
   ```bash
   npm run db:seed:demo
   ```
4. Inicia el servidor:
   ```bash
   npm start
   ```
5. Abre **http://localhost:5000**. El backend sirve también el frontend; no necesitas Live Server.

### Cuentas de demostración
Todas usan la contraseña `Sacm2026!`. Son solo para tu entorno local.

| Rol | Correo |
|---|---|
| Super administrador | `superadmin@sacm.local` |
| Administrador | `admin@sacm.local` |
| Analista | `analista@sacm.local` |
| Usuario | `usuario@sacm.local` |

### Activar la inteligencia externa
CIRCL funciona sin configurar nada. Para las demás, crea una cuenta gratuita y pega la clave en `.env`:

| Servicio | Variable | Registro |
|---|---|---|
| VirusTotal | `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/join-us |
| MalwareBazaar y URLhaus | `ABUSECH_AUTH_KEY` | https://auth.abuse.ch/ |

Luego, en **Sistema → Probar conexión** (super administrador) puedes verificar cada una.

### Scripts útiles
| Comando | Para qué |
|---|---|
| `npm run dev` | Servidor que se reinicia al guardar cambios |
| `npm test` | Pruebas del motor de análisis |
| `npm run samples:analyze` | Analiza las muestras de `samples/` por consola |
| `npm run db:import-legacy` | Importa los usuarios de SACM v1 (conservan su contraseña) |
| `npm run user:create -- "Nombre" correo@x.com "Clave1234" ANALYST` | Crea un usuario |
| `npm run user:reset-password -- correo@x.com "NuevaClave123"` | Cambia una contraseña y desbloquea la cuenta |

### Probar una detección
En **Analizar archivo** usa **"Probar con EICAR"**: genera el archivo de prueba estándar de los antivirus (inofensivo) y SACM lo marca como malicioso con 100 de riesgo. Las muestras de `samples/` son textos con palabras clave que activan las reglas de ransomware, spyware y gusano.

## 📡 API principal

| Método | Ruta | Acceso |
|---|---|---|
| POST | `/api/auth/register` · `/api/auth/login` · `/api/auth/logout` | Público / sesión |
| GET · PATCH | `/api/profile` | Sesión |
| PUT | `/api/profile/password` · `/api/profile/avatar` | Sesión |
| POST · GET | `/api/analyses` | Sesión (el usuario ve solo los suyos) |
| GET | `/api/analyses/:id` · `/:id/status` · `/:id/report` | Dueño o analista |
| POST | `/api/analyses/:id/reviews` · `/:id/reanalyze` | Analista |
| GET | `/api/analytics/overview` · `/iocs` · `/export.csv` | Analista |
| CRUD | `/api/cases` (+ `/notes`, `/analyses`) | Analista |
| CRUD | `/api/admin/users` | Administrador |
| GET | `/api/admin/audit` · `/api/system/overview` | Administrador |
| POST | `/api/system/integrations/:id/test` | Super administrador |

## 🧭 Próximas mejoras
- Reglas YARA reales con `yara-x`.
- Análisis dinámico en sandbox (por ejemplo, CAPE o Hybrid Analysis).
- Notificaciones en tiempo real con WebSockets.
- Despliegue con Docker y pipeline de CI.

> ⚠️ SACM es una herramienta educativa y de apoyo; no reemplaza un antivirus ni un EDR.
