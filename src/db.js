const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const {
  encryptField,
  decryptField,
  hashPassword,
  generateBase32Secret
} = require('./security');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'seguridad_rbac.db');
const db = new DatabaseSync(DB_PATH);

// Habilitar llaves foráneas y modo WAL para concurrencia segura
db.exec('PRAGMA foreign_keys = ON;');
db.exec('PRAGMA journal_mode = WAL;');

function initDatabase() {
  db.exec(`
    -- Tabla de Usuarios (con campos sensibles encriptados con AES-256-GCM)
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      rfc_encrypted TEXT NOT NULL,
      direccion_encrypted TEXT NOT NULL,
      telefono_encrypted TEXT DEFAULT '',
      totp_secret_encrypted TEXT NOT NULL,
      totp_enabled INTEGER DEFAULT 0,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT (datetime('now', 'localtime')),
      updated_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    -- Tabla de Roles
    CREATE TABLE IF NOT EXISTS roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nombre TEXT NOT NULL UNIQUE,
      descripcion TEXT NOT NULL,
      is_system INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    -- Tabla de Permisos específicos por área y acción (Lectura, Escritura, Eliminación)
    CREATE TABLE IF NOT EXISTS permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      codigo TEXT NOT NULL UNIQUE,
      area TEXT NOT NULL,
      accion TEXT NOT NULL,
      nombre TEXT NOT NULL,
      descripcion TEXT NOT NULL
    );

    -- Relación muchos a muchos: Roles <-> Permisos
    CREATE TABLE IF NOT EXISTS role_permissions (
      role_id INTEGER NOT NULL,
      permission_id INTEGER NOT NULL,
      PRIMARY KEY (role_id, permission_id),
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
      FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
    );

    -- Relación muchos a muchos: Usuarios <-> Roles
    CREATE TABLE IF NOT EXISTS user_roles (
      user_id INTEGER NOT NULL,
      role_id INTEGER NOT NULL,
      assigned_at TEXT DEFAULT (datetime('now', 'localtime')),
      PRIMARY KEY (user_id, role_id),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
    );

    -- Historial de Acceso al Sistema (Logins, Logouts, Accesos Denegados, 2FA)
    CREATE TABLE IF NOT EXISTS access_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      email_attempt TEXT NOT NULL,
      usuario_nombre TEXT DEFAULT '',
      evento TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      user_agent TEXT DEFAULT '',
      detalles TEXT DEFAULT '',
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    -- Registro de Auditoría (Acciones realizadas por los usuarios en cada módulo)
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      usuario_nombre TEXT NOT NULL,
      usuario_email TEXT NOT NULL,
      rol_activo TEXT NOT NULL,
      area TEXT NOT NULL,
      accion TEXT NOT NULL,
      recurso_id TEXT DEFAULT '',
      descripcion TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    -- Tokens de Recuperación de Contraseña (Email / SMS / Token 2FA)
    CREATE TABLE IF NOT EXISTS password_resets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT NOT NULL,
      metodo TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    -- Área 1 de Contenido: Documentos y Artículos Corporativos
    CREATE TABLE IF NOT EXISTS documentos (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      categoria TEXT NOT NULL,
      clasificacion TEXT NOT NULL DEFAULT 'INTERNO',
      contenido TEXT NOT NULL,
      notas_confidenciales_encrypted TEXT DEFAULT '',
      autor_id INTEGER,
      autor_nombre TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now', 'localtime')),
      updated_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    -- Área 2 de Contenido: Directorio de Clientes / Proveedores (con RFC y Dirección encriptados)
    CREATE TABLE IF NOT EXISTS clientes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      razon_social TEXT NOT NULL,
      contacto_nombre TEXT NOT NULL,
      email TEXT NOT NULL,
      rfc_encrypted TEXT NOT NULL,
      direccion_encrypted TEXT NOT NULL,
      telefono_encrypted TEXT NOT NULL,
      contrato_monto_encrypted TEXT NOT NULL,
      creado_por TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now', 'localtime')),
      updated_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    -- Historial de Respaldos (Cada 24h y Manuales hacia localidad externa)
    CREATE TABLE IF NOT EXISTS backups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      filename TEXT NOT NULL,
      local_path TEXT NOT NULL,
      external_path TEXT NOT NULL,
      size_bytes INTEGER NOT NULL,
      sha256_hash TEXT NOT NULL,
      encrypted INTEGER DEFAULT 1,
      tipo TEXT NOT NULL,
      ejecutado_por TEXT NOT NULL,
      estado TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now', 'localtime'))
    );

    -- Configuración Global del Sistema (Ruta de USB/Disco externo, intervalo de respaldo, etc.)
    CREATE TABLE IF NOT EXISTS system_config (
      clave TEXT PRIMARY KEY,
      valor TEXT NOT NULL,
      updated_at TEXT DEFAULT (datetime('now', 'localtime'))
    );
  `);

  seedInitialData();
}

function seedInitialData() {
  const roleCount = db.prepare('SELECT COUNT(*) as total FROM roles').get().total;
  if (roleCount > 0) return;

  // 1. Insertar Permisos Granulares por Área y Acción (Lectura, Escritura, Eliminación)
  const permissionsList = [
    // Área: Documentos Corporativos
    ['documentos:lectura', 'Documentos Corporativos', 'Lectura', 'Ver Documentos', 'Acceso a visualizar artículos y documentos del repositorio corporativo.'],
    ['documentos:escritura', 'Documentos Corporativos', 'Escritura', 'Crear y Editar Documentos', 'Permiso para redactar nuevos documentos o modificar existentes.'],
    ['documentos:eliminacion', 'Documentos Corporativos', 'Eliminación', 'Eliminar Documentos', 'Permiso para eliminar documentos del repositorio.'],

    // Área: Directorio de Clientes y Contratos (Datos Fiscales Encriptados)
    ['clientes:lectura', 'Directorio Fiscal de Clientes', 'Lectura', 'Ver Clientes y RFC', 'Acceso para visualizar la cartera de clientes y desencriptar sus datos fiscales (RFC y Dirección).'],
    ['clientes:escritura', 'Directorio Fiscal de Clientes', 'Escritura', 'Crear y Modificar Clientes', 'Permiso para registrar o actualizar clientes con encriptación AES-256 en BD.'],
    ['clientes:eliminacion', 'Directorio Fiscal de Clientes', 'Eliminación', 'Eliminar Clientes', 'Permiso para dar de baja registros de clientes del sistema.'],

    // Área: Gestión de Usuarios
    ['usuarios:lectura', 'Gestión de Usuarios', 'Lectura', 'Ver Usuarios Registrados', 'Permite listar todos los usuarios registrados y ver sus roles asignados.'],
    ['usuarios:escritura', 'Gestión de Usuarios', 'Escritura', 'Gestionar Usuarios y Asignar Roles', 'Permite crear usuarios, activar/desactivar cuentas y asignar o revocar roles.'],
    ['usuarios:eliminacion', 'Gestión de Usuarios', 'Eliminación', 'Eliminar Usuarios', 'Permite eliminar cuentas de usuario del sistema.'],

    // Área: Gestión de Roles y Permisos
    ['roles:lectura', 'Roles y Permisos', 'Lectura', 'Ver Roles y Matriz de Permisos', 'Permite consultar los roles del sistema y sus permisos asociados.'],
    ['roles:escritura', 'Roles y Permisos', 'Escritura', 'Crear Roles y Configurar Permisos', 'Permite crear nuevos roles y asignar o revocar permisos dinámicamente.'],
    ['roles:eliminacion', 'Roles y Permisos', 'Eliminación', 'Eliminar Roles Personalizados', 'Permite eliminar roles creados por el administrador.'],

    // Área: Auditoría e Historial de Accesos
    ['auditoria:lectura', 'Auditoría y Seguridad', 'Lectura', 'Consultar Bitácoras de Auditoría y Accesos', 'Permite inspeccionar el historial de inicios de sesión, acciones de usuarios y el inspector de encriptación en BD.'],

    // Área: Respaldos y Configuración Global
    ['respaldos:lectura', 'Respaldos y Sistema', 'Lectura', 'Ver Estado de Respaldos 24h', 'Permite consultar el historial de respaldos automáticos y ubicación externa.'],
    ['respaldos:escritura', 'Respaldos y Sistema', 'Escritura', 'Ejecutar y Configurar Respaldos Externos', 'Permite disparar respaldos cifrados y configurar la ruta de la USB o disco extraíble.'],
    ['respaldos:eliminacion', 'Respaldos y Sistema', 'Eliminación', 'Depurar Historial de Respaldos', 'Permite eliminar registros antiguos de respaldos locales.']
  ];

  const insertPerm = db.prepare(`
    INSERT INTO permissions (codigo, area, accion, nombre, descripcion)
    VALUES (?, ?, ?, ?, ?)
  `);
  for (const p of permissionsList) {
    insertPerm.run(...p);
  }

  // 2. Insertar los 3 Roles Predeterminados requeridos
  const insertRole = db.prepare(`
    INSERT INTO roles (nombre, descripcion, is_system)
    VALUES (?, ?, 1)
  `);

  const adminRole = insertRole.run(
    'Administrador',
    'Tiene acceso completo a todas las funcionalidades del sistema, incluyendo gestión de usuarios, roles, permisos dinámicos, auditoría y respaldos.'
  );
  const editorRole = insertRole.run(
    'Editor',
    'Puede crear, editar y eliminar contenidos (Documentos y Clientes), pero no puede gestionar usuarios ni configuraciones globales.'
  );
  const regularRole = insertRole.run(
    'Usuario Regular',
    'Solo puede ver y consumir contenido autorizado (permisos de Lectura en áreas operativas).'
  );

  const allPerms = db.prepare('SELECT id, codigo FROM permissions').all();
  const insertRolePerm = db.prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)');

  for (const perm of allPerms) {
    // Administrador tiene todos los permisos
    insertRolePerm.run(adminRole.lastInsertRowid, perm.id);

    // Editor: lectura, escritura y eliminación en contenidos (documentos y clientes)
    if (perm.codigo.startsWith('documentos:') || perm.codigo.startsWith('clientes:')) {
      insertRolePerm.run(editorRole.lastInsertRowid, perm.id);
    }

    // Usuario Regular: únicamente lectura en contenidos (documentos y clientes)
    if (perm.codigo === 'documentos:lectura' || perm.codigo === 'clientes:lectura') {
      insertRolePerm.run(regularRole.lastInsertRowid, perm.id);
    }
  }

  // 3. Crear Usuarios de Demostración para cada Rol Predeterminado
  const insertUser = db.prepare(`
    INSERT INTO users (nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted, totp_secret_encrypted, totp_enabled)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const insertUserRole = db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)');

  // Secretos TOTP fijos de ejemplo para que sea muy fácil probar 2FA en la presentación
  const adminUser = insertUser.run(
    'Carlos Ramírez (Admin)',
    'admin@uni.edu.mx',
    hashPassword('Admin123!'),
    encryptField('RAMC880514HDF'),
    encryptField('Av. Universidad #1024, Col. Narvarte, CDMX, CP 03020'),
    encryptField('55-4123-8900'),
    encryptField('JBSWY3DPEHPK3PXP'),
    0
  );
  insertUserRole.run(adminUser.lastInsertRowid, adminRole.lastInsertRowid);

  const editorUser = insertUser.run(
    'Laura Mendoza (Editora)',
    'editor@uni.edu.mx',
    hashPassword('Editor123!'),
    encryptField('MENL921103MDF'),
    encryptField('Calle Insurgentes Sur #450, Int. 12, Col. Roma Sur, CDMX'),
    encryptField('55-8291-3344'),
    encryptField(generateBase32Secret()),
    0
  );
  insertUserRole.run(editorUser.lastInsertRowid, editorRole.lastInsertRowid);

  const regularUser = insertUser.run(
    'Diego Torres (Usuario Regular)',
    'usuario@uni.edu.mx',
    hashPassword('Usuario123!'),
    encryptField('TORD010822HMC'),
    encryptField('Calzada de Tlalpan #2100, Col. Centinela, Coyoacán, CDMX'),
    encryptField('55-1920-7765'),
    encryptField(generateBase32Secret()),
    0
  );
  insertUserRole.run(regularUser.lastInsertRowid, regularRole.lastInsertRowid);

  // 4. Insertar Documentos Corporativos Iniciales
  const insertDoc = db.prepare(`
    INSERT INTO documentos (titulo, categoria, clasificacion, contenido, notas_confidenciales_encrypted, autor_id, autor_nombre)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  insertDoc.run(
    'Política de Seguridad Perimetral y Segmentación OPNsense',
    'Seguridad de Red',
    'CONFIDENCIAL',
    'El servidor de aplicaciones y base de datos opera dentro de la Red Intermedia (DMZ/LAN controlada) detrás del firewall OPNsense. Las estaciones de trabajo clientes acceden mediante el navegador web al servidor pero tienen restringido el tráfico hacia redes sociales (Facebook, Instagram y X) mediante reglas de filtrado DNS/Firewall.',
    encryptField('IP Servidor Red Intermedia: 192.168.50.10 | Gateway OPNsense: 192.168.50.1 | Regla VLAN activa'),
    adminUser.lastInsertRowid,
    'Carlos Ramírez (Admin)'
  );

  insertDoc.run(
    'Estándar de Encriptación de Datos Sensibles (AES-256-GCM)',
    'Criptografía y Cumplimiento',
    'USO INTERNO',
    'Toda la información sensible almacenada en la base de datos (RFC, Dirección Fiscal, Teléfono y Notas Confidenciales) se cifra en reposo utilizando el algoritmo AES-256-GCM con vectores de inicialización (IV) únicos de 96 bits y etiquetas de autenticación (AuthTag). Las contraseñas se almacenan con derivación criptográfica Scrypt y Salt aleatorio.',
    encryptField('Rotación de llave maestra programada cada semestre. Verificación de integridad SHA-256 en respaldos.'),
    editorUser.lastInsertRowid,
    'Laura Mendoza (Editora)'
  );

  insertDoc.run(
    'Procedimiento de Respaldo Automático Cada 24 Horas',
    'Continuidad de Negocio',
    'PÚBLICO INTERNO',
    'El sistema ejecuta automáticamente un respaldo completo y cifrado de la base de datos cada 24 horas, almacenando una copia local y replicándola hacia una unidad externa segura (USB o Disco Extraíble configurado en el sistema).',
    encryptField('Unidad Externa Primaria: E:\\Respaldos_Seguridad_Uni | Verificación SHA-256 habilitada'),
    adminUser.lastInsertRowid,
    'Carlos Ramírez (Admin)'
  );

  // 5. Insertar Clientes / Proveedores con RFC y Dirección Encriptados
  const insertCliente = db.prepare(`
    INSERT INTO clientes (razon_social, contacto_nombre, email, rfc_encrypted, direccion_encrypted, telefono_encrypted, contrato_monto_encrypted, creado_por)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  insertCliente.run(
    'Grupo Tecnológico Azteca S.A. de C.V.',
    'Ing. Roberto Elizondo',
    'relizondo@tecazteca.mx',
    encryptField('GTA140812K9A'),
    encryptField('Paseo de la Reforma #505, Piso 32, Col. Cuauhtémoc, CDMX, CP 06500'),
    encryptField('55-9001-2233'),
    encryptField('$1,450,000.00 MXN'),
    'Carlos Ramírez (Admin)'
  );

  insertCliente.run(
    'Soluciones Cibernéticas del Norte S. de R.L.',
    'Lic. Sofía Villarreal',
    'svillarreal@cibernorte.com.mx',
    encryptField('SCN1903258P2'),
    encryptField('Av. Lázaro Cárdenas #2400, Zona Valle Oriente, San Pedro Garza García, N.L.'),
    encryptField('81-8345-9910'),
    encryptField('$890,500.00 MXN'),
    'Laura Mendoza (Editora)'
  );

  insertCliente.run(
    'Infraestructura y Redes Seguras Bajío S.A.',
    'Mtro. Fernando Montes',
    'fmontes@redesbajio.mx',
    encryptField('IRS1611047L9'),
    encryptField('Blvd. Bernardo Quintana #7001, Centro Sur, Santiago de Querétaro, Qro.'),
    encryptField('442-215-6070'),
    encryptField('$620,000.00 MXN'),
    'Laura Mendoza (Editora)'
  );

  // 6. Configuración del Sistema por defecto (Ruta de respaldo externo USB / Disco Extraíble)
  const insertConfig = db.prepare('INSERT INTO system_config (clave, valor) VALUES (?, ?)');
  const defaultExternalBackupDir = path.join( path.parse(process.cwd()).root, 'Respaldos_Externos_USB_Seguridad' );
  insertConfig.run('external_backup_path', defaultExternalBackupDir);
  insertConfig.run('backup_interval_hours', '24');
  insertConfig.run('network_encryption_enabled', 'true');

  // 7. Registro inicial de auditoría
  db.prepare(`
    INSERT INTO audit_logs (user_id, usuario_nombre, usuario_email, rol_activo, area, accion, recurso_id, descripcion, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    adminUser.lastInsertRowid,
    'Carlos Ramírez (Admin)',
    'admin@uni.edu.mx',
    'Administrador',
    'Sistema',
    'Inicialización',
    'DB-INIT',
    'Base de datos inicializada con roles predeterminados (Administrador, Editor, Usuario Regular), permisos granulares y encriptación AES-256-GCM.',
    '127.0.0.1'
  );
}

/**
 * Obtiene los roles y permisos efectivos de un usuario
 */
function getUserAuthProfile(userId) {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return null;

  const roles = db.prepare(`
    SELECT r.id, r.nombre, r.descripcion, r.is_system
    FROM roles r
    INNER JOIN user_roles ur ON ur.role_id = r.id
    WHERE ur.user_id = ?
  `).all(userId);

  const permissions = db.prepare(`
    SELECT DISTINCT p.codigo, p.area, p.accion, p.nombre
    FROM permissions p
    INNER JOIN role_permissions rp ON rp.permission_id = p.id
    INNER JOIN user_roles ur ON ur.role_id = rp.role_id
    WHERE ur.user_id = ?
  `).all(userId);

  return {
    id: user.id,
    nombre: user.nombre,
    email: user.email,
    rfc: decryptField(user.rfc_encrypted),
    direccion: decryptField(user.direccion_encrypted),
    telefono: decryptField(user.telefono_encrypted),
    rfc_encrypted: user.rfc_encrypted,
    direccion_encrypted: user.direccion_encrypted,
    totp_enabled: Boolean(user.totp_enabled),
    is_active: Boolean(user.is_active),
    created_at: user.created_at,
    roles: roles,
    roleNames: roles.map(r => r.nombre),
    permissions: permissions.map(p => p.codigo),
    permissionDetails: permissions
  };
}

function logAccess({ userId = null, emailAttempt, usuarioNombre = '', evento, ipAddress, userAgent = '', detalles = '' }) {
  db.prepare(`
    INSERT INTO access_logs (user_id, email_attempt, usuario_nombre, evento, ip_address, user_agent, detalles)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(userId, emailAttempt, usuarioNombre, evento, ipAddress || '127.0.0.1', userAgent || '', detalles);
}

function logAudit({ userId = null, usuarioNombre, usuarioEmail, rolActivo, area, accion, recursoId = '', descripcion, ipAddress }) {
  db.prepare(`
    INSERT INTO audit_logs (user_id, usuario_nombre, usuario_email, rol_activo, area, accion, recurso_id, descripcion, ip_address)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    userId,
    usuarioNombre || 'Sistema',
    usuarioEmail || 'sistema@local',
    rolActivo || 'N/A',
    area,
    accion,
    String(recursoId),
    descripcion,
    ipAddress || '127.0.0.1'
  );
}

module.exports = {
  db,
  DB_PATH,
  DATA_DIR,
  initDatabase,
  getUserAuthProfile,
  logAccess,
  logAudit
};
