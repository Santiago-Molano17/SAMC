# SACM: Sistema de Análisis y Control de Malware

Plataforma web para subir archivos y obtener un **análisis heurístico de malware**: tipo de amenaza, porcentaje de riesgo, comportamientos detectados, áreas del sistema afectadas y recomendaciones. Incluye control de acceso por roles, un panel administrativo con estadísticas y un registro de actividad.

Es un proyecto académico de **Fundamentos de Seguridad Informática**, construido siguiendo buenas prácticas de OWASP.

>  SACM es una herramienta educativa. El motor usa firmas y heurísticas simples; **no reemplaza un antivirus**.


<img width="1364" height="638" alt="image" src="https://github.com/user-attachments/assets/66c4ae74-a5da-4d80-b826-3f1b3b17264b" />
<img width="1357" height="638" alt="image" src="https://github.com/user-attachments/assets/2729e979-0c7f-4152-8aee-6e6ee04a519a" />
<img width="1358" height="619" alt="image" src="https://github.com/user-attachments/assets/01997235-d11c-4a3e-848e-ebba72130a45" />
<img width="1365" height="635" alt="image" src="https://github.com/user-attachments/assets/47d85198-de04-4ed4-a975-657edafe4ebe" />
<img width="1358" height="628" alt="image" src="https://github.com/user-attachments/assets/40c9b686-b98e-4d6f-a59d-774d916ad6f8" />

## Funcionalidades

- **Análisis de archivos:** combina tres señales con pesos (extensión 40 %, nombre 30 %, contenido 30 %) para clasificar Trojan, Ransomware, Spyware, Worm o Rootkit y asignar un nivel de riesgo (Low → Critical).
- **Simulación de impacto:** muestra los procesos y archivos que la amenaza afectaría y una línea de tiempo del ataque.
- **Cuatro roles:** `SUPER_ADMIN`, `ADMIN`, `ANALYST` y `USER`, cada uno con permisos distintos.
- **Panel administrativo:** estadísticas, gráficas por tipo de malware y nivel de riesgo, gestión de usuarios, perfiles, logs y reportes.
- **Panel de usuario:** subir archivos, ver el historial propio y el detalle de cada análisis.
- **Base de conocimiento:** catálogo de familias de malware conocidas.

## Seguridad implementada

| Control | Cómo se implementa |
|---|---|
| Autenticación | JWT firmado con `issuer`/`audience` y expiración de 24 h |
| Contraseñas | Hash con **bcrypt** (12 rondas) y política de complejidad |
| Autorización | Middleware de roles en cada ruta (RBAC) |
| IDOR | Un `USER` solo puede consultar sus propios análisis |
| XSS | Escape de todo dato controlado por el usuario antes de renderizarlo |
| Inyección SQL | Consultas parametrizadas en todas las rutas (`mysql2`) |
| Subida de archivos | Límite de tamaño, nombres saneados (sin path traversal) |
| Cabeceras HTTP | `helmet` |
| Fuerza bruta / DoS | `express-rate-limit` (100 peticiones cada 15 min por IP) |
| Auditoría | Registro de actividad en `activity_logs` |
| Secretos | Variables de entorno (`.env` fuera del repositorio) |

## Tecnologías

**Backend:** Node.js, Express 5, MySQL (`mysql2`), JWT, bcryptjs, Multer, Helmet
**Frontend:** HTML, CSS, JavaScript, Bootstrap 5, Chart.js, Font Awesome
**Base de datos:** MySQL 8

## Estructura

```
SACM/
├── Backend/
│   ├── server.js              # Servidor Express
│   ├── db.js                  # Conexión MySQL
│   ├── create-admin.js        # Crea el super admin inicial
│   ├── analyze_samples.js     # Analiza las muestras de prueba
│   ├── middleware/            # JWT, roles y logs de actividad
│   ├── routes/                # auth, files (subida/análisis), dashboard
│   └── services/
│       └── malwareAnalyzer.js # Motor de análisis heurístico
├── frontend/                  # Login, registro y paneles
├── Database/sacm.sql          # Esquema y datos iniciales
├── muestras_seguras/          # Muestras de prueba INOFENSIVAS (solo texto)
└── analysis_outputs/          # Resultados de ejemplo de esas muestras
```

## Cómo ejecutarlo

**Requisitos:** Node.js 18 o superior y MySQL 8.

1. **Base de datos:** ejecuta el script en MySQL (Workbench o consola):
   ```bash
   mysql -u root -p < Database/sacm.sql
   ```

2. **Variables de entorno:** copia `Backend/.env.example` como `Backend/.env` y completa tus datos. Para generar un `JWT_SECRET` seguro:
   ```bash
   node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
   ```

3. **Dependencias:**
   ```bash
   npm run setup
   ```

4. **Crea el super admin** (los usuarios que se registran desde la web quedan con rol `USER`):
   ```bash
   npm run create-admin -- "Tu Nombre" admin@ejemplo.com "Contrasena123"
   ```

5. **Inicia el backend** (queda en `http://localhost:5000`):
   ```bash
   npm start
   ```

6. **Abre el frontend:** abre `frontend/login.html` en el navegador, o sírvelo con la extensión Live Server de VS Code.

## Probar con las muestras seguras

La carpeta `muestras_seguras/` trae archivos de texto **sin código malicioso real**. Solo contienen palabras clave que activan las firmas de ransomware, spyware y worm. Súbelos desde el panel de usuario, o analízalos por consola:

```bash
npm --prefix Backend run analyze-samples
```

| Muestra | Clasificación | Riesgo |
|---|---|---|
| `ransomware_demo.txt` | Ransomware | 95 % |
| `spyware_demo.txt` | Spyware | 85 % |
| `worm_demo.txt` | Worm | 80 % |

## API principal

| Método | Ruta | Acceso |
|---|---|---|
| POST | `/api/auth/register` | Público |
| POST | `/api/auth/login` | Público |
| POST | `/api/files/upload` | Usuario autenticado |
| GET | `/api/files/my-analysis` | Usuario autenticado |
| GET | `/api/files/analysis/:id` | Dueño del análisis o ADMIN/ANALYST |
| GET | `/api/dashboard/stats` | SUPER_ADMIN, ADMIN, ANALYST |
| GET | `/api/dashboard/users` | SUPER_ADMIN, ADMIN, ANALYST |
| DELETE | `/api/dashboard/users/:id` | SUPER_ADMIN, ADMIN |
| PUT | `/api/dashboard/users/:id/role` | SUPER_ADMIN |

## Próximas mejoras

- Integrar hashes contra bases públicas (por ejemplo, la API de VirusTotal).
- Reglas YARA para el análisis de contenido.
- Eliminar el archivo del disco después de analizarlo.
- Pruebas automatizadas y despliegue con Docker.
