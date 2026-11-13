const express = require('express');
const path = require('node:path');
const fs = require('node:fs');
const crypto = require('node:crypto');

const {
  NETWORK_SHARED_HEX,
  encryptField,
  decryptField,
  decryptNetworkPayloadMiddleware,
  hashPassword,
  verifyPassword,
  generateBase32Secret,
  generateTotpToken,
  verifyTotpToken,
  generateNumericOtp,
  hashToken
} = require('./src/security');

const {
  db,
  initDatabase,
  getUserAuthProfile,
  logAccess,
  logAudit
} = require('./src/db');

const {
  detectAvailableDrives,
  getExternalBackupPath,
  performBackup,
  startBackupScheduler
} = require('./src/backupService');

const {
  sendRecoveryCode,
  getRecentMessages
} = require('./src/mailService');

// Inicializar Base de Datos y Planificador de Respaldos 24h
initDatabase();
startBackupScheduler();

const app = express();
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(decryptNetworkPayloadMiddleware);

// Servir archivos estáticos del Frontend Responsivo
app.use(express.static(path.join(__dirname, 'public')));

// Almacén de sesiones activas y retos 2FA pendientes
const activeSessions = new Map();
const pending2FAChallenges = new Map();

function getClientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.socket?.remoteAddress || '127.0.0.1';
}

/**
 * Middleware de Autenticación (Verifica Token de Sesión y recarga permisos en tiempo real)
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : (req.query.token || '');

  if (!token || !activeSessions.has(token)) {
    return res.status(401).json({ error: 'Sesión no válida o expirada. Por favor inicie sesión.' });
  }

  const sessionData = activeSessions.get(token);
  const profile = getUserAuthProfile(sessionData.userId);

  if (!profile || !profile.is_active) {
    activeSessions.delete(token);
    return res.status(403).json({ error: 'La cuenta de usuario ha sido desactivada o eliminada.' });
  }

  req.user = profile;
  req.sessionToken = token;
  next();
}

/**
 * Middleware de Control de Acceso Basado en Roles y Permisos (RBAC Dinámico)
 */
function requirePermission(permissionCode) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'No autenticado' });
    }
    const hasPerm = req.user.permissions.includes(permissionCode) || req.user.roleNames.includes('Administrador');
    if (!hasPerm) {
      const ip = getClientIp(req);
      logAccess({
        userId: req.user.id,
        emailAttempt: req.user.email,
        usuarioNombre: req.user.nombre,
        evento: 'ACCESS_DENIED',
        ipAddress: ip,
        userAgent: req.headers['user-agent'] || '',
        detalles: `Intento bloqueado por falta de permiso requerido: [${permissionCode}] en ruta ${req.method} ${req.originalUrl}`
      });
      logAudit({
        userId: req.user.id,
        usuarioNombre: req.user.nombre,
        usuarioEmail: req.user.email,
        rolActivo: req.user.roleNames.join(', '),
        area: 'Control de Acceso',
        accion: 'Acceso Denegado (403)',
        recursoId: permissionCode,
        descripcion: `Bloqueo de seguridad: El usuario intentó ejecutar una acción sin el permiso '${permissionCode}'.`,
        ipAddress: ip
      });
      return res.status(403).json({
        error: `Acceso Denegado: Tu rol actual (${req.user.roleNames.join(', ')}) no cuenta con el permiso '${permissionCode}'.`
      });
    }
    next();
  };
}

// ============================================================================
// 1. ENDPOINTS DE CONFIGURACIÓN CRIPTOGRÁFICA EN RED Y ESTADO PÚBLICO
// ============================================================================
app.get('/api/security/handshake', (req, res) => {
  res.json({
    networkEncryptionAlgorithm: 'AES-256-GCM',
    dbEncryptionAlgorithm: 'AES-256-GCM + Scrypt',
    sharedKeyHex: NETWORK_SHARED_HEX
  });
});

// ============================================================================
// 2. GESTIÓN DE USUARIOS: REGISTRO, LOGIN, 2FA, CAMBIO Y RECUPERACIÓN DE CONTRASEÑA
// ============================================================================

// Registrar usuario nuevo (Nombre, Email, Contraseña + RFC y Dirección encriptados)
app.post('/api/auth/register', (req, res) => {
  try {
    const { nombre, email, password, rfc, direccion, telefono } = req.body;
    const ip = getClientIp(req);

    if (!nombre || !email || !password) {
      return res.status(400).json({ error: 'Los campos Nombre, Email y Contraseña(s) son obligatorios.' });
    }
    if (String(password).length < 6) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const existing = db.prepare('SELECT id FROM users WHERE LOWER(email) = ?').get(cleanEmail);
    if (existing) {
      return res.status(409).json({ error: 'Ya existe un usuario registrado con ese correo electrónico.' });
    }

    const totpSecret = generateBase32Secret();
    const result = db.prepare(`
      INSERT INTO users (nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted, totp_secret_encrypted, totp_enabled)
      VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `).run(
      nombre.trim(),
      cleanEmail,
      hashPassword(password),
      encryptField(rfc || 'XAXX010101000'),
      encryptField(direccion || 'Dirección Confidencial Registrada'),
      encryptField(telefono || 'Sin teléfono'),
      encryptField(totpSecret)
    );

    // Por defecto se asigna el rol "Usuario Regular" (Principio de Menor Privilegio)
    const regularRole = db.prepare('SELECT id FROM roles WHERE nombre = ?').get('Usuario Regular');
    if (regularRole) {
      db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)').run(result.lastInsertRowid, regularRole.id);
    }

    logAccess({
      userId: result.lastInsertRowid,
      emailAttempt: cleanEmail,
      usuarioNombre: nombre.trim(),
      evento: 'USER_REGISTERED',
      ipAddress: ip,
      userAgent: req.headers['user-agent'] || '',
      detalles: 'Registro de nuevo usuario con rol predeterminado Usuario Regular y datos encriptados AES-256.'
    });

    logAudit({
      userId: result.lastInsertRowid,
      usuarioNombre: nombre.trim(),
      usuarioEmail: cleanEmail,
      rolActivo: 'Usuario Regular',
      area: 'Gestión de Usuarios',
      accion: 'Registro de Cuenta',
      recursoId: result.lastInsertRowid,
      descripcion: `Nuevo usuario registrado (${cleanEmail}). Contraseña hasheada con Scrypt y RFC/Dirección encriptados con AES-256-GCM.`,
      ipAddress: ip
    });

    res.status(201).json({
      message: 'Usuario registrado exitosamente con rol de Usuario Regular. Ahora puedes iniciar sesión.',
      userId: result.lastInsertRowid
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al registrar usuario: ' + err.message });
  }
});

// Iniciar sesión
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = getClientIp(req);
    const userAgent = req.headers['user-agent'] || '';

    if (!email || !password) {
      return res.status(400).json({ error: 'Ingresa tu correo electrónico y contraseña.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(cleanEmail);

    if (!user || !verifyPassword(password, user.password_hash)) {
      logAccess({
        userId: user ? user.id : null,
        emailAttempt: cleanEmail,
        usuarioNombre: user ? user.nombre : 'Desconocido',
        evento: 'LOGIN_FAILED',
        ipAddress: ip,
        userAgent,
        detalles: 'Credenciales inválidas (contraseña incorrecta o usuario inexistente).'
      });
      return res.status(401).json({ error: 'Correo electrónico o contraseña incorrectos.' });
    }

    if (!user.is_active) {
      logAccess({
        userId: user.id,
        emailAttempt: cleanEmail,
        usuarioNombre: user.nombre,
        evento: 'LOGIN_BLOCKED',
        ipAddress: ip,
        userAgent,
        detalles: 'Intento de acceso con cuenta desactivada.'
      });
      return res.status(403).json({ error: 'Tu cuenta está desactivada. Contacta al Administrador.' });
    }

    // Si el usuario tiene activada la Verificación en 2 Pasos (2FA)
    if (user.totp_enabled) {
      const challengeId = crypto.randomBytes(24).toString('hex');
      const totpSecret = decryptField(user.totp_secret_encrypted);
      pending2FAChallenges.set(challengeId, {
        userId: user.id,
        expiresAt: Date.now() + 5 * 60 * 1000
      });

      return res.json({
        requires2FA: true,
        challengeId,
        email: user.email,
        demoCurrentTotp: generateTotpToken(totpSecret), // Para demostración rápida en clase
        message: 'Ingresa el código de 6 dígitos de tu aplicación autenticadora (2FA).'
      });
    }

    // Crear sesión activa
    const sessionToken = crypto.randomBytes(32).toString('hex');
    activeSessions.set(sessionToken, {
      userId: user.id,
      createdAt: Date.now(),
      ipAddress: ip
    });

    const profile = getUserAuthProfile(user.id);

    logAccess({
      userId: user.id,
      emailAttempt: user.email,
      usuarioNombre: user.nombre,
      evento: 'LOGIN_SUCCESS',
      ipAddress: ip,
      userAgent,
      detalles: `Inicio de sesión exitoso con rol(es): ${profile.roleNames.join(', ')}`
    });

    res.json({
      token: sessionToken,
      user: profile
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al iniciar sesión: ' + err.message });
  }
});

// Verificar segundo factor (2FA TOTP) durante login
app.post('/api/auth/verify-2fa', (req, res) => {
  const { challengeId, token2fa } = req.body;
  const ip = getClientIp(req);
  const userAgent = req.headers['user-agent'] || '';

  const challenge = pending2FAChallenges.get(challengeId);
  if (!challenge || challenge.expiresAt < Date.now()) {
    pending2FAChallenges.delete(challengeId);
    return res.status(401).json({ error: 'El reto de verificación 2FA expiró. Inicia sesión nuevamente.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(challenge.userId);
  const secret = decryptField(user.totp_secret_encrypted);

  if (!verifyTotpToken(secret, token2fa)) {
    logAccess({
      userId: user.id,
      emailAttempt: user.email,
      usuarioNombre: user.nombre,
      evento: '2FA_FAILED',
      ipAddress: ip,
      userAgent,
      detalles: 'Código TOTP de segundo factor inválido.'
    });
    return res.status(401).json({ error: 'Código de verificación 2FA incorrecto.' });
  }

  pending2FAChallenges.delete(challengeId);
  const sessionToken = crypto.randomBytes(32).toString('hex');
  activeSessions.set(sessionToken, {
    userId: user.id,
    createdAt: Date.now(),
    ipAddress: ip
  });

  const profile = getUserAuthProfile(user.id);
  logAccess({
    userId: user.id,
    emailAttempt: user.email,
    usuarioNombre: user.nombre,
    evento: 'LOGIN_2FA_SUCCESS',
    ipAddress: ip,
    userAgent,
    detalles: `Inicio de sesión con 2FA TOTP exitoso. Roles: ${profile.roleNames.join(', ')}`
  });

  res.json({
    token: sessionToken,
    user: profile
  });
});

// Cerrar sesión
app.post('/api/auth/logout', requireAuth, (req, res) => {
  const ip = getClientIp(req);
  logAccess({
    userId: req.user.id,
    emailAttempt: req.user.email,
    usuarioNombre: req.user.nombre,
    evento: 'LOGOUT',
    ipAddress: ip,
    userAgent: req.headers['user-agent'] || '',
    detalles: 'Cierre de sesión voluntario por el usuario.'
  });
  activeSessions.delete(req.sessionToken);
  res.json({ message: 'Sesión cerrada correctamente.' });
});

// Obtener perfil y permisos actualizados de la sesión abierta
app.get('/api/auth/me', requireAuth, (req, res) => {
  const rawUser = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const totpSecret = decryptField(rawUser.totp_secret_encrypted);
  res.json({
    user: req.user,
    totpSetup: {
      secret: totpSecret,
      enabled: Boolean(rawUser.totp_enabled),
      currentCode: generateTotpToken(totpSecret),
      otpauthUrl: `otpauth://totp/SeguridadUni:${encodeURIComponent(req.user.email)}?secret=${totpSecret}&issuer=SeguridadComputo`
    }
  });
});

// Cambiar contraseña desde la misma aplicación al tener una sesión abierta
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const ip = getClientIp(req);

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Debes proporcionar tu contraseña actual y la nueva contraseña.' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ error: 'La nueva contraseña debe tener mínimo 6 caracteres.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!verifyPassword(currentPassword, user.password_hash)) {
    logAudit({
      userId: req.user.id,
      usuarioNombre: req.user.nombre,
      usuarioEmail: req.user.email,
      rolActivo: req.user.roleNames.join(', '),
      area: 'Seguridad de Cuenta',
      accion: 'Cambio de Contraseña Fallido',
      recursoId: req.user.id,
      descripcion: 'Intento fallido de cambio de contraseña (contraseña actual incorrecta).',
      ipAddress: ip
    });
    return res.status(401).json({ error: 'La contraseña actual proporcionada es incorrecta.' });
  }

  db.prepare(`
    UPDATE users SET password_hash = ?, updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(hashPassword(newPassword), req.user.id);

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Seguridad de Cuenta',
    accion: 'Cambio de Contraseña',
    recursoId: req.user.id,
    descripcion: 'El usuario actualizó su contraseña desde una sesión activa.',
    ipAddress: ip
  });

  res.json({ message: 'Contraseña actualizada exitosamente con encriptación Scrypt.' });
});

// Actualizar datos sensibles propios (RFC, Dirección, Teléfono) o activar/desactivar 2FA
app.put('/api/auth/profile', requireAuth, (req, res) => {
  const { nombre, rfc, direccion, telefono, totp_enabled } = req.body;
  const ip = getClientIp(req);

  db.prepare(`
    UPDATE users
    SET nombre = ?,
        rfc_encrypted = ?,
        direccion_encrypted = ?,
        telefono_encrypted = ?,
        totp_enabled = ?,
        updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(
    nombre || req.user.nombre,
    encryptField(rfc || req.user.rfc),
    encryptField(direccion || req.user.direccion),
    encryptField(telefono || req.user.telefono),
    totp_enabled ? 1 : 0,
    req.user.id
  );

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Seguridad de Cuenta',
    accion: 'Actualización de Perfil / 2FA',
    recursoId: req.user.id,
    descripcion: `Perfil actualizado. Datos sensibles (RFC y Dirección) re-encriptados con AES-256-GCM. Estado 2FA: ${totp_enabled ? 'Activado' : 'Desactivado'}.`,
    ipAddress: ip
  });

  res.json({
    message: 'Perfil y configuración 2FA actualizados correctamente.',
    user: getUserAuthProfile(req.user.id)
  });
});

// Solicitar recuperación de contraseña (por Correo Electrónico, SMS o Token 2FA)
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email, metodo = 'EMAIL' } = req.body;
    const ip = getClientIp(req);

    if (!email) {
      return res.status(400).json({ error: 'Ingresa tu correo electrónico registrado.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(cleanEmail);
    if (!user) {
      return res.status(404).json({ error: 'No se encontró ninguna cuenta asociada a ese correo electrónico.' });
    }

    if (metodo === '2FA_TOTP') {
      const totpSecret = decryptField(user.totp_secret_encrypted);
      logAccess({
        userId: user.id,
        emailAttempt: user.email,
        usuarioNombre: user.nombre,
        evento: 'PASSWORD_RECOVERY_REQUEST',
        ipAddress: ip,
        detalles: 'Solicitud de recuperación mediante Token TOTP de Verificación en 2 Pasos.'
      });
      return res.json({
        metodo: '2FA_TOTP',
        message: 'Ingresa el código actual de 6 dígitos de tu autenticador TOTP (2FA) para restablecer tu contraseña.',
        demoTotpHint: generateTotpToken(totpSecret)
      });
    }

    // Generar código OTP de 6 dígitos para Correo Electrónico o Mensaje de Texto (SMS)
    const otpCode = generateNumericOtp(6);
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutos

    db.prepare(`
      INSERT INTO password_resets (user_id, token_hash, metodo, expires_at, used)
      VALUES (?, ?, ?, ?, 0)
    `).run(user.id, hashToken(otpCode), metodo, expiresAt);

    const notification = await sendRecoveryCode({
      toEmail: user.email,
      nombre: user.nombre,
      codigo: otpCode,
      metodo: metodo === 'SMS' ? `Mensaje de Texto SMS (${decryptField(user.telefono_encrypted)})` : 'Correo Electrónico'
    });

    logAccess({
      userId: user.id,
      emailAttempt: user.email,
      usuarioNombre: user.nombre,
      evento: 'PASSWORD_RECOVERY_OTP_SENT',
      ipAddress: ip,
      detalles: `Código de recuperación enviado vía ${metodo} (${notification.smtpInfo}).`
    });

    res.json({
      metodo,
      message: metodo === 'SMS'
        ? `Se envió un código de verificación por SMS al número registrado de ${user.nombre}.`
        : `Se envió un código de verificación de 6 dígitos al correo ${user.email}.`,
      simulatedNotification: notification
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al procesar solicitud de recuperación: ' + err.message });
  }
});

// Confirmar recuperación de contraseña con código (Email, SMS o Token 2FA)
app.post('/api/auth/reset-password', (req, res) => {
  const { email, codigo, newPassword, metodo = 'EMAIL' } = req.body;
  const ip = getClientIp(req);

  if (!email || !codigo || !newPassword) {
    return res.status(400).json({ error: 'Todos los campos (correo, código de verificación y nueva contraseña) son obligatorios.' });
  }
  if (String(newPassword).length < 6) {
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
  }

  const cleanEmail = String(email).trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE LOWER(email) = ?').get(cleanEmail);
  if (!user) {
    return res.status(404).json({ error: 'Usuario no encontrado.' });
  }

  let verified = false;

  if (metodo === '2FA_TOTP') {
    const secret = decryptField(user.totp_secret_encrypted);
    verified = verifyTotpToken(secret, codigo);
  } else {
    const resetRow = db.prepare(`
      SELECT * FROM password_resets
      WHERE user_id = ? AND token_hash = ? AND used = 0 AND expires_at > ?
      ORDER BY id DESC LIMIT 1
    `).get(user.id, hashToken(String(codigo).trim()), Date.now());

    if (resetRow) {
      verified = true;
      db.prepare('UPDATE password_resets SET used = 1 WHERE id = ?').run(resetRow.id);
    }
  }

  if (!verified) {
    logAccess({
      userId: user.id,
      emailAttempt: user.email,
      usuarioNombre: user.nombre,
      evento: 'PASSWORD_RESET_FAILED',
      ipAddress: ip,
      detalles: `Código de recuperación inválido o expirado (${metodo}).`
    });
    return res.status(401).json({ error: 'El código de verificación en dos pasos es inválido o ha expirado.' });
  }

  db.prepare(`
    UPDATE users SET password_hash = ?, updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(hashPassword(newPassword), user.id);

  logAccess({
    userId: user.id,
    emailAttempt: user.email,
    usuarioNombre: user.nombre,
    evento: 'PASSWORD_RESET_SUCCESS',
    ipAddress: ip,
    detalles: `Contraseña restablecida exitosamente mediante verificación en dos pasos (${metodo}).`
  });

  logAudit({
    userId: user.id,
    usuarioNombre: user.nombre,
    usuarioEmail: user.email,
    rolActivo: 'Recuperación 2FA',
    area: 'Seguridad de Cuenta',
    accion: 'Recuperación de Contraseña',
    recursoId: user.id,
    descripcion: `Contraseña restablecida mediante verificación de token (${metodo}).`,
    ipAddress: ip
  });

  res.json({ message: '¡Contraseña restablecida con éxito! Ya puedes iniciar sesión con tu nueva contraseña.' });
});

// Consultar bandeja de mensajes OTP enviados (útil para demostración sin internet en lab OPNsense)
app.get('/api/auth/simulated-inbox', (req, res) => {
  res.json({ messages: getRecentMessages() });
});

// ============================================================================
// 3. ÁREA DE CONTENIDO 1: DOCUMENTOS CORPORATIVOS (Controlado por Permisos)
// ============================================================================
app.get('/api/documentos', requireAuth, requirePermission('documentos:lectura'), (req, res) => {
  const rows = db.prepare('SELECT * FROM documentos ORDER BY id DESC').all();
  const formatted = rows.map(doc => ({
    ...doc,
    notas_confidenciales: decryptField(doc.notas_confidenciales_encrypted)
  }));
  res.json({ documentos: formatted });
});

app.post('/api/documentos', requireAuth, requirePermission('documentos:escritura'), (req, res) => {
  const { titulo, categoria, clasificacion, contenido, notas_confidenciales } = req.body;
  const ip = getClientIp(req);

  if (!titulo || !contenido) {
    return res.status(400).json({ error: 'El título y el contenido del documento son obligatorios.' });
  }

  const result = db.prepare(`
    INSERT INTO documentos (titulo, categoria, clasificacion, contenido, notas_confidenciales_encrypted, autor_id, autor_nombre)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    titulo.trim(),
    categoria || 'General',
    clasificacion || 'USO INTERNO',
    contenido.trim(),
    encryptField(notas_confidenciales || ''),
    req.user.id,
    req.user.nombre
  );

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Documentos Corporativos',
    accion: 'Escritura (Creación)',
    recursoId: result.lastInsertRowid,
    descripcion: `Creó el documento "${titulo.trim()}" con notas confidenciales encriptadas en BD.`,
    ipAddress: ip
  });

  res.status(201).json({ message: 'Documento creado exitosamente.', id: result.lastInsertRowid });
});

app.put('/api/documentos/:id', requireAuth, requirePermission('documentos:escritura'), (req, res) => {
  const { id } = req.params;
  const { titulo, categoria, clasificacion, contenido, notas_confidenciales } = req.body;
  const ip = getClientIp(req);

  const existing = db.prepare('SELECT * FROM documentos WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Documento no encontrado.' });

  db.prepare(`
    UPDATE documentos
    SET titulo = ?, categoria = ?, clasificacion = ?, contenido = ?, notas_confidenciales_encrypted = ?, updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(
    titulo || existing.titulo,
    categoria || existing.categoria,
    clasificacion || existing.clasificacion,
    contenido || existing.contenido,
    encryptField(notas_confidenciales !== undefined ? notas_confidenciales : decryptField(existing.notas_confidenciales_encrypted)),
    id
  );

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Documentos Corporativos',
    accion: 'Escritura (Edición)',
    recursoId: id,
    descripcion: `Modificó el documento #${id} ("${titulo || existing.titulo}").`,
    ipAddress: ip
  });

  res.json({ message: 'Documento actualizado correctamente.' });
});

app.delete('/api/documentos/:id', requireAuth, requirePermission('documentos:eliminacion'), (req, res) => {
  const { id } = req.params;
  const ip = getClientIp(req);

  const existing = db.prepare('SELECT * FROM documentos WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Documento no encontrado.' });

  db.prepare('DELETE FROM documentos WHERE id = ?').run(id);

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Documentos Corporativos',
    accion: 'Eliminación',
    recursoId: id,
    descripcion: `Eliminó permanentemente el documento #${id} ("${existing.titulo}").`,
    ipAddress: ip
  });

  res.json({ message: 'Documento eliminado correctamente.' });
});

// ============================================================================
// 4. ÁREA DE CONTENIDO 2: CLIENTES CON RFC Y DIRECCIÓN ENCRIPTADOS EN BD Y RED
// ============================================================================
app.get('/api/clientes', requireAuth, requirePermission('clientes:lectura'), (req, res) => {
  const rows = db.prepare('SELECT * FROM clientes ORDER BY id DESC').all();
  const clientes = rows.map(c => ({
    id: c.id,
    razon_social: c.razon_social,
    contacto_nombre: c.contacto_nombre,
    email: c.email,
    rfc: decryptField(c.rfc_encrypted),
    direccion: decryptField(c.direccion_encrypted),
    telefono: decryptField(c.telefono_encrypted),
    contrato_monto: decryptField(c.contrato_monto_encrypted),
    rfc_encrypted: c.rfc_encrypted,
    direccion_encrypted: c.direccion_encrypted,
    telefono_encrypted: c.telefono_encrypted,
    contrato_monto_encrypted: c.contrato_monto_encrypted,
    creado_por: c.creado_por,
    created_at: c.created_at,
    updated_at: c.updated_at
  }));
  res.json({ clientes });
});

app.post('/api/clientes', requireAuth, requirePermission('clientes:escritura'), (req, res) => {
  const { razon_social, contacto_nombre, email, rfc, direccion, telefono, contrato_monto } = req.body;
  const ip = getClientIp(req);

  if (!razon_social || !rfc || !direccion) {
    return res.status(400).json({ error: 'Razón Social, RFC y Dirección son obligatorios.' });
  }

  const result = db.prepare(`
    INSERT INTO clientes (razon_social, contacto_nombre, email, rfc_encrypted, direccion_encrypted, telefono_encrypted, contrato_monto_encrypted, creado_por)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    razon_social.trim(),
    (contacto_nombre || 'Contacto Principal').trim(),
    (email || 'contacto@cliente.mx').trim(),
    encryptField(rfc.trim().toUpperCase()),
    encryptField(direccion.trim()),
    encryptField(telefono || 'S/N'),
    encryptField(contrato_monto || '$0.00 MXN'),
    req.user.nombre
  );

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Directorio Fiscal de Clientes',
    accion: 'Escritura (Creación)',
    recursoId: result.lastInsertRowid,
    descripcion: `Registró cliente "${razon_social.trim()}" con RFC y Dirección encriptados con AES-256-GCM en BD y en tránsito.`,
    ipAddress: ip
  });

  res.status(201).json({ message: 'Cliente registrado con datos sensibles encriptados en BD.', id: result.lastInsertRowid });
});

app.put('/api/clientes/:id', requireAuth, requirePermission('clientes:escritura'), (req, res) => {
  const { id } = req.params;
  const { razon_social, contacto_nombre, email, rfc, direccion, telefono, contrato_monto } = req.body;
  const ip = getClientIp(req);

  const existing = db.prepare('SELECT * FROM clientes WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Cliente no encontrado.' });

  db.prepare(`
    UPDATE clientes
    SET razon_social = ?,
        contacto_nombre = ?,
        email = ?,
        rfc_encrypted = ?,
        direccion_encrypted = ?,
        telefono_encrypted = ?,
        contrato_monto_encrypted = ?,
        updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(
    razon_social || existing.razon_social,
    contacto_nombre || existing.contacto_nombre,
    email || existing.email,
    encryptField(rfc || decryptField(existing.rfc_encrypted)),
    encryptField(direccion || decryptField(existing.direccion_encrypted)),
    encryptField(telefono || decryptField(existing.telefono_encrypted)),
    encryptField(contrato_monto || decryptField(existing.contrato_monto_encrypted)),
    id
  );

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Directorio Fiscal de Clientes',
    accion: 'Escritura (Edición)',
    recursoId: id,
    descripcion: `Actualizó datos fiscales encriptados del cliente #${id} ("${razon_social || existing.razon_social}").`,
    ipAddress: ip
  });

  res.json({ message: 'Datos del cliente actualizados y re-encriptados.' });
});

app.delete('/api/clientes/:id', requireAuth, requirePermission('clientes:eliminacion'), (req, res) => {
  const { id } = req.params;
  const ip = getClientIp(req);

  const existing = db.prepare('SELECT * FROM clientes WHERE id = ?').get(id);
  if (!existing) return res.status(404).json({ error: 'Cliente no encontrado.' });

  db.prepare('DELETE FROM clientes WHERE id = ?').run(id);

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Directorio Fiscal de Clientes',
    accion: 'Eliminación',
    recursoId: id,
    descripcion: `Eliminó el registro fiscal del cliente #${id} ("${existing.razon_social}").`,
    ipAddress: ip
  });

  res.json({ message: 'Cliente eliminado del directorio.' });
});

// ============================================================================
// 5. DASHBOARD DE ADMINISTRACIÓN: GESTIÓN DE USUARIOS, ROLES Y PERMISOS DINÁMICOS
// ============================================================================

// Listar todos los usuarios registrados
app.get('/api/admin/users', requireAuth, requirePermission('usuarios:lectura'), (req, res) => {
  const users = db.prepare('SELECT id FROM users ORDER BY id ASC').all();
  const detailed = users.map(u => getUserAuthProfile(u.id));
  res.json({ users: detailed });
});

// Asignar o revocar roles a un usuario (y activar/desactivar cuenta)
app.put('/api/admin/users/:id/roles', requireAuth, requirePermission('usuarios:escritura'), (req, res) => {
  const targetUserId = Number(req.params.id);
  const { roleIds, is_active } = req.body;
  const ip = getClientIp(req);

  const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(targetUserId);
  if (!targetUser) return res.status(404).json({ error: 'Usuario no encontrado.' });

  if (!Array.isArray(roleIds) || roleIds.length === 0) {
    return res.status(400).json({ error: 'El usuario debe tener al menos un rol asignado.' });
  }

  db.prepare('DELETE FROM user_roles WHERE user_id = ?').run(targetUserId);
  const insertUR = db.prepare('INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)');
  for (const rId of roleIds) {
    insertUR.run(targetUserId, Number(rId));
  }

  if (typeof is_active === 'boolean') {
    db.prepare('UPDATE users SET is_active = ?, updated_at = datetime(\'now\', \'localtime\') WHERE id = ?')
      .run(is_active ? 1 : 0, targetUserId);
  }

  const updatedProfile = getUserAuthProfile(targetUserId);

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Gestión de Usuarios',
    accion: 'Asignación/Revocación de Roles',
    recursoId: targetUserId,
    descripcion: `Actualizó los roles de "${targetUser.nombre}" (${targetUser.email}) a: [${updatedProfile.roleNames.join(', ')}]. Estado activo: ${updatedProfile.is_active}.`,
    ipAddress: ip
  });

  res.json({
    message: `Roles de ${targetUser.nombre} actualizados correctamente.`,
    user: updatedProfile
  });
});

// Eliminar un usuario
app.delete('/api/admin/users/:id', requireAuth, requirePermission('usuarios:eliminacion'), (req, res) => {
  const targetUserId = Number(req.params.id);
  const ip = getClientIp(req);

  if (targetUserId === req.user.id) {
    return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta de administrador con sesión activa.' });
  }

  const targetUser = db.prepare('SELECT * FROM users WHERE id = ?').get(targetUserId);
  if (!targetUser) return res.status(404).json({ error: 'Usuario no encontrado.' });

  db.prepare('DELETE FROM users WHERE id = ?').run(targetUserId);

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Gestión de Usuarios',
    accion: 'Eliminación',
    recursoId: targetUserId,
    descripcion: `Eliminó la cuenta del usuario "${targetUser.nombre}" (${targetUser.email}).`,
    ipAddress: ip
  });

  res.json({ message: 'Usuario eliminado correctamente.' });
});

// Obtener todos los roles y el catálogo completo de permisos por área
app.get('/api/admin/roles', requireAuth, requirePermission('roles:lectura'), (req, res) => {
  const roles = db.prepare('SELECT * FROM roles ORDER BY id ASC').all();
  const permissions = db.prepare('SELECT * FROM permissions ORDER BY id ASC').all();
  const rolePerms = db.prepare('SELECT * FROM role_permissions').all();

  const rolesWithPerms = roles.map(r => {
    const pIds = rolePerms.filter(rp => rp.role_id === r.id).map(rp => rp.permission_id);
    const pCodes = permissions.filter(p => pIds.includes(p.id)).map(p => p.codigo);
    const userCount = db.prepare('SELECT COUNT(*) as total FROM user_roles WHERE role_id = ?').get(r.id).total;
    return {
      ...r,
      is_system: Boolean(r.is_system),
      permissionIds: pIds,
      permissionCodes: pCodes,
      userCount
    };
  });

  res.json({
    roles: rolesWithPerms,
    permissions
  });
});

// Crear un nuevo rol y asignarle permisos dinámicamente
app.post('/api/admin/roles', requireAuth, requirePermission('roles:escritura'), (req, res) => {
  const { nombre, descripcion, permissionIds = [] } = req.body;
  const ip = getClientIp(req);

  if (!nombre || !descripcion) {
    return res.status(400).json({ error: 'El nombre y la descripción del rol son obligatorios.' });
  }

  const existing = db.prepare('SELECT id FROM roles WHERE LOWER(nombre) = ?').get(nombre.trim().toLowerCase());
  if (existing) {
    return res.status(409).json({ error: 'Ya existe un rol con ese nombre.' });
  }

  const result = db.prepare(`
    INSERT INTO roles (nombre, descripcion, is_system)
    VALUES (?, ?, 0)
  `).run(nombre.trim(), descripcion.trim());

  const newRoleId = result.lastInsertRowid;
  const insertRP = db.prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
  for (const pId of permissionIds) {
    insertRP.run(newRoleId, Number(pId));
  }

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Roles y Permisos',
    accion: 'Creación de Rol',
    recursoId: newRoleId,
    descripcion: `Creó el nuevo rol "${nombre.trim()}" con ${permissionIds.length} permisos asignados.`,
    ipAddress: ip
  });

  res.status(201).json({ message: `Rol "${nombre.trim()}" creado exitosamente.`, id: newRoleId });
});

// Actualizar permisos asignados a un rol de forma dinámica
app.put('/api/admin/roles/:id/permissions', requireAuth, requirePermission('roles:escritura'), (req, res) => {
  const roleId = Number(req.params.id);
  const { permissionIds = [], descripcion } = req.body;
  const ip = getClientIp(req);

  const role = db.prepare('SELECT * FROM roles WHERE id = ?').get(roleId);
  if (!role) return res.status(404).json({ error: 'Rol no encontrado.' });

  if (descripcion) {
    db.prepare('UPDATE roles SET descripcion = ? WHERE id = ?').run(descripcion.trim(), roleId);
  }

  db.prepare('DELETE FROM role_permissions WHERE role_id = ?').run(roleId);
  const insertRP = db.prepare('INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)');
  for (const pId of permissionIds) {
    insertRP.run(roleId, Number(pId));
  }

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Roles y Permisos',
    accion: 'Actualización Dinámica de Permisos',
    recursoId: roleId,
    descripcion: `Actualizó dinámicamente la matriz de permisos del rol "${role.nombre}" (${permissionIds.length} permisos activos).`,
    ipAddress: ip
  });

  res.json({ message: `Permisos del rol "${role.nombre}" actualizados en tiempo real.` });
});

// Eliminar un rol personalizado
app.delete('/api/admin/roles/:id', requireAuth, requirePermission('roles:eliminacion'), (req, res) => {
  const roleId = Number(req.params.id);
  const ip = getClientIp(req);

  const role = db.prepare('SELECT * FROM roles WHERE id = ?').get(roleId);
  if (!role) return res.status(404).json({ error: 'Rol no encontrado.' });
  if (role.is_system) {
    return res.status(400).json({ error: 'Los 3 roles predeterminados del sistema (Administrador, Editor, Usuario Regular) no pueden eliminarse, solo editar sus permisos.' });
  }

  db.prepare('DELETE FROM roles WHERE id = ?').run(roleId);

  logAudit({
    userId: req.user.id,
    usuarioNombre: req.user.nombre,
    usuarioEmail: req.user.email,
    rolActivo: req.user.roleNames.join(', '),
    area: 'Roles y Permisos',
    accion: 'Eliminación de Rol',
    recursoId: roleId,
    descripcion: `Eliminó el rol personalizado "${role.nombre}".`,
    ipAddress: ip
  });

  res.json({ message: `Rol "${role.nombre}" eliminado correctamente.` });
});

// ============================================================================
// 6. AUDITORÍA, HISTORIAL DE ACCESOS E INSPECTOR DE ENCRIPTACIÓN EN BD
// ============================================================================
app.get('/api/admin/logs', requireAuth, requirePermission('auditoria:lectura'), (req, res) => {
  const auditLogs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 250').all();
  const accessLogs = db.prepare('SELECT * FROM access_logs ORDER BY id DESC LIMIT 250').all();

  // Inspector en vivo de cómo están almacenados los datos cifrados en las tablas de la BD
  const rawUsersSample = db.prepare(`
    SELECT id, nombre, email, password_hash, rfc_encrypted, direccion_encrypted, telefono_encrypted
    FROM users ORDER BY id ASC
  `).all().map(u => ({
    ...u,
    rfc_decrypted: decryptField(u.rfc_encrypted),
    direccion_decrypted: decryptField(u.direccion_encrypted)
  }));

  const rawClientesSample = db.prepare(`
    SELECT id, razon_social, rfc_encrypted, direccion_encrypted, contrato_monto_encrypted
    FROM clientes ORDER BY id ASC
  `).all().map(c => ({
    ...c,
    rfc_decrypted: decryptField(c.rfc_encrypted),
    direccion_decrypted: decryptField(c.direccion_encrypted),
    contrato_monto_decrypted: decryptField(c.contrato_monto_encrypted)
  }));

  res.json({
    auditLogs,
    accessLogs,
    encryptionInspector: {
      users: rawUsersSample,
      clientes: rawClientesSample
    }
  });
});

// ============================================================================
// 7. GESTIÓN DE RESPALDOS AUTOMÁTICOS (CADA 24 HORAS) EN LOCALIDAD EXTERNA (USB)
// ============================================================================
app.get('/api/admin/backups', requireAuth, requirePermission('respaldos:lectura'), (req, res) => {
  const backups = db.prepare('SELECT * FROM backups ORDER BY id DESC LIMIT 50').all();
  const externalPath = getExternalBackupPath();
  const drives = detectAvailableDrives();
  res.json({
    backups,
    externalPath,
    intervalHours: 24,
    drives
  });
});

app.post('/api/admin/backups/run', requireAuth, requirePermission('respaldos:escritura'), (req, res) => {
  const ip = getClientIp(req);
  const { customExternalPath } = req.body;

  if (customExternalPath && String(customExternalPath).trim()) {
    db.prepare(`
      INSERT INTO system_config (clave, valor, updated_at)
      VALUES ('external_backup_path', ?, datetime('now', 'localtime'))
      ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor, updated_at = excluded.updated_at
    `).run(String(customExternalPath).trim());
  }

  const backupInfo = performBackup({
    tipo: 'MANUAL_VERIFICADO',
    ejecutadoPor: req.user.nombre,
    userId: req.user.id,
    ipAddress: ip
  });

  res.json({
    message: 'Respaldo cifrado generado y almacenado en la localidad externa configurada.',
    backup: backupInfo
  });
});

app.get('/api/admin/backups/:id/download', requireAuth, requirePermission('respaldos:lectura'), (req, res) => {
  const backup = db.prepare('SELECT * FROM backups WHERE id = ?').get(req.params.id);
  if (!backup || !fs.existsSync(backup.local_path)) {
    return res.status(404).json({ error: 'Archivo de respaldo no encontrado.' });
  }
  res.download(backup.local_path, backup.filename);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log('===================================================================');
  console.log(' SISTEMA DE GESTIÓN DE ROLES Y PERMISOS (RBAC) - SEGURIDAD CÓMPUTO');
  console.log('===================================================================');
  console.log(` Servidor Web escuchando en : http://localhost:${PORT}`);
  console.log(` Acceso en Red Intermedia   : http://0.0.0.0:${PORT}`);
  console.log(' Encriptación en BD y Red   : AES-256-GCM + Scrypt Activo');
  console.log(' Respaldo Automático 24h    : Activo (Local + Unidad Externa USB)');
  console.log('===================================================================');
});
