# Proyecto Final: Seguridad en Cómputo
## Implementación de Aplicación con Gestión de Roles y Permisos de Usuario (RBAC) bajo un Ambiente Controlado

Este proyecto implementa el sistema completo solicitado en el documento de requerimientos de **Seguridad en Cómputo**, incluyendo autenticación, autorización dinámica basada en roles y permisos, verificación en dos pasos (2FA), encriptación de datos sensibles (**AES-256-GCM** y **Scrypt**) tanto en la Base de Datos como en tránsito por red, bitácoras de auditoría e historial de accesos, y respaldos automáticos cada 24 horas hacia una localidad externa (USB / Disco extraíble).

---

## 1. Ejecución Rápida

```bash
cd C:\ProyectoFinalUni
npm install
npm start
```

- **URL Local en el Servidor**: `http://localhost:3000`
- **URL desde Máquinas Clientes (Red Intermedia OPNsense)**: `http://<IP_DEL_SERVIDOR_VM>:3000` (o puerto `80` con Apache/IIS).

### Cuentas Predeterminadas para Demostración

| Rol Predeterminado | Correo Electrónico | Contraseña | Permisos Iniciales |
| :--- | :--- | :--- | :--- |
| **Administrador** | `admin@uni.edu.mx` | `Admin123!` | Acceso completo a usuarios, roles, matriz de permisos, auditoría, respaldos y contenidos. |
| **Editor** | `editor@uni.edu.mx` | `Editor123!` | Puede crear, editar y eliminar contenidos (Documentos y Clientes), sin gestión de usuarios ni configuración global. |
| **Usuario Regular** | `usuario@uni.edu.mx` | `Usuario123!` | Solo puede visualizar y consumir contenido (`Lectura`). |

---

## 2. Cumplimiento de Requerimientos Funcionales y No Funcionales

1. **Gestión de Usuarios**:
   - Registro de nuevos usuarios con `Nombre`, `Email`, `Contraseña`, además de datos sensibles (`RFC`, `Dirección Fiscal` y `Teléfono`).
   - Inicio de sesión con soporte para **Verificación en Dos Pasos (2FA TOTP)**.
   - **Cambio de contraseña con sesión abierta** desde el módulo *Mi Perfil, Contraseña y 2FA*.
   - **Recuperación de contraseña en 2 pasos** eligiendo entre:
     - **Correo Electrónico (SMTP / Bandeja Virtual en pantalla)**
     - **Mensaje de Texto SMS**
     - **Token TOTP (Google Authenticator)**
2. **Gestión de Roles y Permisos Dinámicos**:
   - Tres roles predeterminados: **Administrador**, **Editor** y **Usuario Regular**.
   - Permisos granulares específicos por área y acción (**Lectura**, **Escritura**, **Eliminación**).
   - Creación de nuevos roles y asignación/revocación dinámica de permisos en tiempo real desde el **Dashboard de Administración**.
3. **Control de Acceso y Bitácoras**:
   - Validación en cada endpoint del servidor y en la interfaz.
   - **Historial de Acceso al Sistema**: registra logins exitosos, fallidos, verificaciones 2FA, cierres de sesión e intentos bloqueados (`403 ACCESS_DENIED`).
   - **Registro de Auditoría**: guarda cada acción realizada por los usuarios con fecha, hora, rol activo, módulo, descripción e IP.
4. **Seguridad Lógica y de Datos (Encriptación y Respaldos 24h)**:
   - **Encriptación en Base de Datos**: Contraseñas con hash criptográfico `Scrypt + Salt` y campos sensibles (`RFC`, `Dirección`, `Teléfono`, `Monto`, `Notas Confidenciales`) cifrados con **AES-256-GCM** (`enc:v1:<iv>:<authTag>:<ciphertext>`). Incluye un **Inspector de Encriptación en BD** en vivo dentro de la pestaña *Auditoría, Accesos y BD*.
   - **Encriptación en Red (En Tránsito)**: El navegador cifra los campos sensibles con **WebCrypto API AES-256-GCM** (`net:v1:...`) antes de transmitirlos por la red hacia el servidor.
   - **Respaldo Automático cada 24 Horas en Localidad Externa (USB / Disco Extraíble)**: Planificador integrado cada 24h + script CLI (`npm run backup`) + script de Tarea Programada de Windows (`scripts/registrar_tarea_respaldo_24h.ps1`) + selector de unidad USB en la interfaz web.

---

## 3. Guía de Configuración en la VM Servidor y Firewall OPNsense

### A. Servidor Web (Apache o IIS) y Base de Datos en la VM (Red Intermedia)
1. En la máquina virtual del servidor ubicada en la **Red Intermedia (DMZ/OPT1)**, coloca la carpeta `C:\ProyectoFinalUni` y ejecuta `npm start`.
2. Para exponerlo por el puerto `80` a través de **Apache** o **IIS**:
   - **Apache**: Usa el archivo [infraestructura/apache-vhost.conf](file:///C:/ProyectoFinalUni/infraestructura/apache-vhost.conf).
   - **IIS (Windows Server)**: Usa el archivo [infraestructura/web.config](file:///C:/ProyectoFinalUni/infraestructura/web.config).
3. Si el docente solicita revisar las tablas en **MySQL / MariaDB**, importa el archivo [infraestructura/database_mysql.sql](file:///C:/ProyectoFinalUni/infraestructura/database_mysql.sql).

### B. Configuración de OPNsense (Red Intermedia + Bloqueo de Redes Sociales en Clientes)

1. **Permitir que la Red de Clientes (LAN) acceda al Servidor Web en la Red Intermedia (OPT1/DMZ)**:
   - En OPNsense ve a **Firewall -> Rules -> LAN**.
   - Agrega una regla `Pass`, Protocolo `TCP`, Source `LAN net`, Destination `<IP_SERVIDOR_RED_INTERMEDIA>`, Destination Port `80` y `3000`.
2. **Permitir que el Servidor (Red Intermedia) tenga acceso libre a Internet**:
   - En **Firewall -> Rules -> OPT1 (Red Intermedia)**, agrega una regla `Pass`, Protocolo `Any`, Source `OPT1 net`, Destination `any`.
3. **Bloquear Redes Sociales (Facebook, Instagram y X/Twitter) únicamente para las Máquinas Clientes**:
   - **Método 1 (Firewall Alias por Dominios/IPs en LAN)**:
     1. Ve a **Firewall -> Aliases -> Add**.
     2. Nombre: `RedesSociales_Bloqueadas`, Tipo: `Hosts`.
     3. Contenido: `facebook.com`, `www.facebook.com`, `instagram.com`, `www.instagram.com`, `twitter.com`, `x.com`, `www.x.com`, `t.co`, `fbcdn.net`, `cdninstagram.com`.
     4. Ve a **Firewall -> Rules -> LAN** y coloca **arriba** de la regla de salida a Internet una regla con Action: `Block` (o `Reject`), Source: `LAN net`, Destination: `RedesSociales_Bloqueadas`, Protocol: `TCP/UDP`.
   - **Método 2 (Unbound DNS Blocklist + Regla por Vista/Subred)**:
     - En **Services -> Unbound DNS -> Blocklist** o **Overrides**, redirige `facebook.com`, `instagram.com`, `x.com` y `twitter.com` a `0.0.0.0` para los clientes que usan el DNS del firewall, mientras el servidor en la Red Intermedia usa un DNS externo (`8.8.8.8` / `1.1.1.1`) teniendo salida libre.
