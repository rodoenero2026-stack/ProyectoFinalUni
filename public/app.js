let authToken = localStorage.getItem('rbac_token') || '';
let currentUser = null;
let sharedNetworkKeyHex = '';
let pendingChallengeId = '';
let showCiphertextClientes = false;
let cachedRolesData = [];
let cachedPermissionsData = [];

// ============================================================================
// UTILIDADES DE NOTIFICACIÓN Y CIFRADO EN RED (AES-256-GCM)
// ============================================================================
function showToast(msg, type = 'info') {
  const container = document.getElementById('toast-container');
  const div = document.createElement('div');
  div.className = `toast ${type}`;
  div.textContent = msg;
  container.appendChild(div);
  setTimeout(() => div.remove(), 4500);
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Encripta un campo sensible en el navegador antes de enviarlo por la red usando WebCrypto AES-256-GCM
 */
async function encryptForNetwork(plainText) {
  if (!plainText) return '';
  if (window.crypto && window.crypto.subtle && sharedNetworkKeyHex) {
    try {
      const keyBytes = hexToBytes(sharedNetworkKeyHex);
      const cryptoKey = await window.crypto.subtle.importKey(
        'raw',
        keyBytes,
        { name: 'AES-GCM' },
        false,
        ['encrypt']
      );
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(String(plainText));
      const encryptedBuf = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        cryptoKey,
        encoded
      );
      const cipherHex = bytesToHex(new Uint8Array(encryptedBuf));
      const netToken = `net:v1:${bytesToHex(iv)}:${cipherHex}`;
      const preview = document.getElementById('network-payload-preview');
      if (preview) {
        preview.textContent = `Paquete Cifrado en Tránsito (AES-256-GCM):\n${netToken}`;
      }
      return netToken;
    } catch (_) {
      return plainText;
    }
  }
  return plainText;
}

async function apiFetch(url, options = {}) {
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {})
  };
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }
  const response = await fetch(url, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `Error HTTP ${response.status}`);
  }
  return data;
}

// ============================================================================
// INICIALIZACIÓN
// ============================================================================
window.addEventListener('DOMContentLoaded', async () => {
  try {
    const hs = await apiFetch('/api/security/handshake');
    sharedNetworkKeyHex = hs.sharedKeyHex;
  } catch (_) {}

  refreshSimulatedInbox();

  if (authToken) {
    await reloadCurrentUserProfile();
  }
});

// ============================================================================
// AUTENTICACIÓN, REGISTRO Y RECUPERACIÓN EN 2 PASOS
// ============================================================================
function switchAuthTab(tab) {
  const tabs = document.querySelectorAll('#auth-view .auth-tab');
  tabs.forEach((t, idx) => {
    t.classList.toggle('active',
      (tab === 'login' && idx === 0) ||
      (tab === 'register' && idx === 1) ||
      (tab === 'recover' && idx === 2)
    );
  });

  document.getElementById('form-login').classList.toggle('hidden', tab !== 'login');
  document.getElementById('form-2fa').classList.add('hidden');
  document.getElementById('form-register').classList.toggle('hidden', tab !== 'register');
  document.getElementById('form-recover').classList.toggle('hidden', tab !== 'recover');
}

function fillDemoLogin(email, pass) {
  switchAuthTab('login');
  document.getElementById('login-email').value = email;
  document.getElementById('login-password').value = pass;
  document.getElementById('form-login').requestSubmit();
}

async function handleLogin(e) {
  e.preventDefault();
  try {
    const email = document.getElementById('login-email').value.trim();
    const rawPass = document.getElementById('login-password').value;
    const encryptedPass = await encryptForNetwork(rawPass);

    const res = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password: encryptedPass })
    });

    if (res.requires2FA) {
      pendingChallengeId = res.challengeId;
      document.getElementById('form-login').classList.add('hidden');
      document.getElementById('form-2fa').classList.remove('hidden');
      document.getElementById('2fa-challenge-msg').innerHTML =
        `${res.message}<br/><strong>Código TOTP actual (Demostración): <span style="color:#34d399">${res.demoCurrentTotp}</span></strong>`;
      document.getElementById('login-2fa-code').value = res.demoCurrentTotp;
      showToast('Se requiere segundo factor de autenticación (2FA TOTP)', 'info');
      return;
    }

    authToken = res.token;
    localStorage.setItem('rbac_token', authToken);
    currentUser = res.user;
    showToast(`Bienvenido(a), ${currentUser.nombre}`, 'success');
    await reloadCurrentUserProfile();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleVerify2FA(e) {
  e.preventDefault();
  try {
    const token2fa = document.getElementById('login-2fa-code').value.trim();
    const res = await apiFetch('/api/auth/verify-2fa', {
      method: 'POST',
      body: JSON.stringify({ challengeId: pendingChallengeId, token2fa })
    });

    authToken = res.token;
    localStorage.setItem('rbac_token', authToken);
    currentUser = res.user;
    showToast('Verificación 2FA exitosa. Sesión iniciada.', 'success');
    await reloadCurrentUserProfile();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleRegister(e) {
  e.preventDefault();
  try {
    const nombre = document.getElementById('reg-nombre').value.trim();
    const email = document.getElementById('reg-email').value.trim();
    const password = await encryptForNetwork(document.getElementById('reg-password').value);
    const rfc = await encryptForNetwork(document.getElementById('reg-rfc').value.trim().toUpperCase());
    const direccion = await encryptForNetwork(document.getElementById('reg-direccion').value.trim());
    const telefono = await encryptForNetwork(document.getElementById('reg-telefono').value.trim());

    const res = await apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ nombre, email, password, rfc, direccion, telefono })
    });

    showToast(res.message, 'success');
    document.getElementById('form-register').reset();
    switchAuthTab('login');
    document.getElementById('login-email').value = email;
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleForgotPassword(e) {
  e.preventDefault();
  try {
    const email = document.getElementById('rec-email').value.trim();
    const metodo = document.getElementById('rec-metodo').value;

    const res = await apiFetch('/api/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email, metodo })
    });

    showToast(res.message, 'success');

    if (res.demoTotpHint) {
      document.getElementById('rec-codigo').value = res.demoTotpHint;
      showToast(`Token TOTP 2FA generado: ${res.demoTotpHint}`, 'info');
    } else if (res.simulatedNotification && res.simulatedNotification.codigo) {
      document.getElementById('rec-codigo').value = res.simulatedNotification.codigo;
    }

    await refreshSimulatedInbox();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleResetPassword(e) {
  e.preventDefault();
  try {
    const email = document.getElementById('rec-email').value.trim();
    const metodo = document.getElementById('rec-metodo').value;
    const codigo = document.getElementById('rec-codigo').value.trim();
    const newPassword = await encryptForNetwork(document.getElementById('rec-new-pass').value);

    const res = await apiFetch('/api/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ email, metodo, codigo, newPassword })
    });

    showToast(res.message, 'success');
    switchAuthTab('login');
    document.getElementById('login-email').value = email;
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function refreshSimulatedInbox() {
  try {
    const res = await apiFetch('/api/auth/simulated-inbox');
    const box = document.getElementById('simulated-inbox-list');
    if (!res.messages || res.messages.length === 0) {
      box.innerHTML = 'Aún no se han solicitado códigos de recuperación en esta sesión.';
      return;
    }
    box.innerHTML = res.messages.slice(0, 4).map(m => `
      <div style="background:#0f172a; border:1px solid #334155; padding:8px 10px; border-radius:8px; margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between;">
          <strong style="color:#38bdf8;">${m.metodo}</strong>
          <span style="font-size:11px; color:#64748b;">${m.timestamp}</span>
        </div>
        <div>Para: <strong>${m.to}</strong></div>
        <div style="margin-top:4px;">Código Verificación 2FA: <strong style="color:#34d399; font-size:14px; letter-spacing:2px;">${m.codigo}</strong></div>
      </div>
    `).join('');
  } catch (_) {}
}

async function handleLogout() {
  try {
    await apiFetch('/api/auth/logout', { method: 'POST' });
  } catch (_) {}
  authToken = '';
  currentUser = null;
  localStorage.removeItem('rbac_token');
  document.getElementById('app-view').classList.add('hidden');
  document.getElementById('auth-view').classList.remove('hidden');
  switchAuthTab('login');
  showToast('Sesión cerrada correctamente.', 'info');
}

// ============================================================================
// CARGA DE PERFIL Y CONTROL DE ACCESO DINÁMICO EN LA INTERFAZ
// ============================================================================
function hasPerm(code) {
  if (!currentUser) return false;
  return currentUser.permissions.includes(code) || currentUser.roleNames.includes('Administrador');
}

async function reloadCurrentUserProfile() {
  try {
    const data = await apiFetch('/api/auth/me');
    currentUser = data.user;

    document.getElementById('auth-view').classList.add('hidden');
    document.getElementById('app-view').classList.remove('hidden');

    // Poblar barra lateral
    document.getElementById('sidebar-user-name').textContent = currentUser.nombre;
    document.getElementById('sidebar-user-email').textContent = currentUser.email;
    document.getElementById('sidebar-user-roles').innerHTML = currentUser.roleNames
      .map(r => `<span class="role-badge">${r}</span>`).join('');

    // Mostrar/ocultar elementos del menú según permisos dinámicos del usuario
    document.getElementById('nav-documentos').classList.toggle('hidden', !hasPerm('documentos:lectura'));
    document.getElementById('nav-clientes').classList.toggle('hidden', !hasPerm('clientes:lectura'));
    document.getElementById('nav-usuarios').classList.toggle('hidden', !hasPerm('usuarios:lectura'));
    document.getElementById('nav-roles').classList.toggle('hidden', !hasPerm('roles:lectura'));
    document.getElementById('nav-auditoria').classList.toggle('hidden', !hasPerm('auditoria:lectura'));
    document.getElementById('nav-respaldos').classList.toggle('hidden', !hasPerm('respaldos:lectura'));

    // Botones de creación según permisos de escritura
    document.getElementById('btn-new-doc').classList.toggle('hidden', !hasPerm('documentos:escritura'));
    document.getElementById('btn-new-cliente').classList.toggle('hidden', !hasPerm('clientes:escritura'));

    // Resumen de estadísticas
    document.getElementById('stat-roles').textContent = currentUser.roleNames.join(', ');
    document.getElementById('stat-perms-count').textContent = currentUser.permissions.length;
    document.getElementById('stat-user-rfc').textContent = currentUser.rfc;
    document.getElementById('stat-user-2fa').textContent = currentUser.totp_enabled ? 'ACTIVO (TOTP)' : 'Opcional';

    // Insignias de permisos efectivos
    const badgesContainer = document.getElementById('user-permissions-badges');
    badgesContainer.innerHTML = currentUser.permissionDetails.map(p => {
      let cls = 'perm-lectura';
      if (p.accion === 'Escritura') cls = 'perm-escritura';
      if (p.accion === 'Eliminación') cls = 'perm-eliminacion';
      return `<span class="perm-badge ${cls}">${p.area}: <strong>${p.accion}</strong> (${p.codigo})</span>`;
    }).join('');

    // Poblar formulario Mi Perfil y 2FA
    document.getElementById('prof-nombre').value = currentUser.nombre;
    document.getElementById('prof-rfc').value = currentUser.rfc;
    document.getElementById('prof-direccion').value = currentUser.direccion;
    document.getElementById('prof-telefono').value = currentUser.telefono;
    document.getElementById('prof-2fa-enabled').checked = Boolean(currentUser.totp_enabled);
    if (data.totpSetup) {
      document.getElementById('prof-totp-secret').textContent = data.totpSetup.secret;
      document.getElementById('prof-totp-current').textContent = data.totpSetup.currentCode;
    }

    showSection('sec-resumen');
  } catch (err) {
    authToken = '';
    localStorage.removeItem('rbac_token');
    document.getElementById('app-view').classList.add('hidden');
    document.getElementById('auth-view').classList.remove('hidden');
  }
}

function showSection(sectionId) {
  document.querySelectorAll('.app-section').forEach(sec => {
    sec.classList.toggle('hidden', sec.id !== sectionId);
  });
  document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.section === sectionId);
  });

  if (sectionId === 'sec-documentos') loadDocumentos();
  if (sectionId === 'sec-clientes') loadClientes();
  if (sectionId === 'sec-usuarios') loadAdminUsers();
  if (sectionId === 'sec-roles') loadAdminRoles();
  if (sectionId === 'sec-auditoria') loadAuditAndAccessLogs();
  if (sectionId === 'sec-respaldos') loadBackups();
}

async function simulateUnauthorizedAttempt() {
  try {
    await apiFetch('/api/admin/roles', {
      method: 'POST',
      body: JSON.stringify({ nombre: 'RolPruebaIntruso', descripcion: 'Prueba de control de acceso' })
    });
    showToast('Tienes rol de Administrador: la operación fue autorizada. Prueba con Usuario Regular o Editor para ver el bloqueo 403.', 'info');
  } catch (err) {
    showToast(err.message + ' (Registrado en Historial de Accesos y Auditoría)', 'error');
  }
}

// ============================================================================
// ÁREA 1: DOCUMENTOS CORPORATIVOS
// ============================================================================
async function loadDocumentos() {
  try {
    const res = await apiFetch('/api/documentos');
    const container = document.getElementById('documentos-list');
    const canWrite = hasPerm('documentos:escritura');
    const canDelete = hasPerm('documentos:eliminacion');

    container.innerHTML = res.documentos.map(doc => `
      <div class="card">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:12px;">
          <div>
            <span class="role-badge">${doc.clasificacion}</span>
            <span style="font-size:12px; color:var(--text-secondary);">${doc.categoria} • Autor: ${doc.autor_nombre} • ${doc.created_at}</span>
            <h3 style="font-size:16px; margin-top:6px; color:#f8fafc;">${doc.titulo}</h3>
          </div>
          <div style="display:flex; gap:6px;">
            ${canWrite ? `<button class="btn btn-secondary btn-sm" onclick='editDoc(${JSON.stringify(doc).replace(/'/g, "&#39;")})'>Editar</button>` : ''}
            ${canDelete ? `<button class="btn btn-danger btn-sm" onclick="deleteDoc(${doc.id})">Eliminar</button>` : ''}
          </div>
        </div>
        <p style="font-size:13.5px; color:#cbd5e1; margin-top:10px;">${doc.contenido}</p>
        ${doc.notas_confidenciales ? `
          <div style="margin-top:12px; padding:8px 12px; background:#090d16; border:1px solid #1e293b; border-radius:8px; font-size:12px;">
            <strong style="color:#34d399;">Nota Confidencial (Desencriptada AES-256-GCM):</strong> ${doc.notas_confidenciales}
          </div>
        ` : ''}
      </div>
    `).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function openDocModal() {
  document.getElementById('doc-form-card').classList.remove('hidden');
  document.getElementById('doc-form-title').textContent = 'Crear Nuevo Documento Corporativo';
  document.getElementById('doc-id').value = '';
  document.getElementById('doc-titulo').value = '';
  document.getElementById('doc-categoria').value = '';
  document.getElementById('doc-contenido').value = '';
  document.getElementById('doc-notas').value = '';
}

function closeDocModal() {
  document.getElementById('doc-form-card').classList.add('hidden');
}

function editDoc(doc) {
  document.getElementById('doc-form-card').classList.remove('hidden');
  document.getElementById('doc-form-title').textContent = `Editar Documento #${doc.id}`;
  document.getElementById('doc-id').value = doc.id;
  document.getElementById('doc-titulo').value = doc.titulo;
  document.getElementById('doc-categoria').value = doc.categoria;
  document.getElementById('doc-clasificacion').value = doc.clasificacion;
  document.getElementById('doc-contenido').value = doc.contenido;
  document.getElementById('doc-notas').value = doc.notas_confidenciales || '';
}

async function handleSaveDoc(e) {
  e.preventDefault();
  try {
    const id = document.getElementById('doc-id').value;
    const payload = {
      titulo: document.getElementById('doc-titulo').value.trim(),
      categoria: document.getElementById('doc-categoria').value.trim(),
      clasificacion: document.getElementById('doc-clasificacion').value,
      contenido: document.getElementById('doc-contenido').value.trim(),
      notas_confidenciales: await encryptForNetwork(document.getElementById('doc-notas').value.trim())
    };

    if (id) {
      await apiFetch(`/api/documentos/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
      showToast('Documento actualizado correctamente.', 'success');
    } else {
      await apiFetch('/api/documentos', { method: 'POST', body: JSON.stringify(payload) });
      showToast('Documento creado exitosamente.', 'success');
    }
    closeDocModal();
    loadDocumentos();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteDoc(id) {
  try {
    await apiFetch(`/api/documentos/${id}`, { method: 'DELETE' });
    showToast('Documento eliminado.', 'success');
    loadDocumentos();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// ÁREA 2: CLIENTES CON RFC Y DIRECCIÓN ENCRIPTADOS EN BD Y RED
// ============================================================================
function toggleShowCiphertextClientes() {
  showCiphertextClientes = !showCiphertextClientes;
  loadClientes();
}

async function loadClientes() {
  try {
    const res = await apiFetch('/api/clientes');
    const tbody = document.getElementById('clientes-tbody');
    const canWrite = hasPerm('clientes:escritura');
    const canDelete = hasPerm('clientes:eliminacion');

    tbody.innerHTML = res.clientes.map(c => `
      <tr>
        <td>
          <strong>${c.razon_social}</strong><br/>
          <span style="font-size:12px; color:var(--text-secondary);">${c.contacto_nombre} (${c.email})</span>
        </td>
        <td>
          ${showCiphertextClientes
            ? `<span class="cipher-code">${c.rfc_encrypted}</span>`
            : `<strong style="color:#34d399;">${c.rfc}</strong>`
          }
        </td>
        <td>
          ${showCiphertextClientes
            ? `<span class="cipher-code">${c.direccion_encrypted}</span>`
            : `<span>${c.direccion}</span>`
          }
        </td>
        <td>
          ${showCiphertextClientes
            ? `<span class="cipher-code">${c.contrato_monto_encrypted}</span>`
            : `<div>${c.telefono}</div><strong style="color:#38bdf8;">${c.contrato_monto}</strong>`
          }
        </td>
        <td>
          <div style="display:flex; gap:6px;">
            ${canWrite ? `<button class="btn btn-secondary btn-sm" onclick='editCliente(${JSON.stringify(c).replace(/'/g, "&#39;")})'>Editar</button>` : '<span style="font-size:11px; color:#64748b;">Solo lectura</span>'}
            ${canDelete ? `<button class="btn btn-danger btn-sm" onclick="deleteCliente(${c.id})">Eliminar</button>` : ''}
          </div>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

function openClienteModal() {
  document.getElementById('cliente-form-card').classList.remove('hidden');
  document.getElementById('cliente-form-title').textContent = 'Registrar Nuevo Cliente (Cifrado AES-256)';
  document.getElementById('cli-id').value = '';
  document.getElementById('cli-razon').value = '';
  document.getElementById('cli-contacto').value = '';
  document.getElementById('cli-rfc').value = '';
  document.getElementById('cli-email').value = '';
  document.getElementById('cli-telefono').value = '';
  document.getElementById('cli-monto').value = '';
  document.getElementById('cli-direccion').value = '';
}

function closeClienteModal() {
  document.getElementById('cliente-form-card').classList.add('hidden');
}

function editCliente(c) {
  document.getElementById('cliente-form-card').classList.remove('hidden');
  document.getElementById('cliente-form-title').textContent = `Editar Cliente #${c.id}`;
  document.getElementById('cli-id').value = c.id;
  document.getElementById('cli-razon').value = c.razon_social;
  document.getElementById('cli-contacto').value = c.contacto_nombre;
  document.getElementById('cli-rfc').value = c.rfc;
  document.getElementById('cli-email').value = c.email;
  document.getElementById('cli-telefono').value = c.telefono;
  document.getElementById('cli-monto').value = c.contrato_monto;
  document.getElementById('cli-direccion').value = c.direccion;
}

async function handleSaveCliente(e) {
  e.preventDefault();
  try {
    const id = document.getElementById('cli-id').value;
    const payload = {
      razon_social: document.getElementById('cli-razon').value.trim(),
      contacto_nombre: document.getElementById('cli-contacto').value.trim(),
      email: document.getElementById('cli-email').value.trim(),
      rfc: await encryptForNetwork(document.getElementById('cli-rfc').value.trim().toUpperCase()),
      direccion: await encryptForNetwork(document.getElementById('cli-direccion').value.trim()),
      telefono: await encryptForNetwork(document.getElementById('cli-telefono').value.trim()),
      contrato_monto: await encryptForNetwork(document.getElementById('cli-monto').value.trim())
    };

    if (id) {
      await apiFetch(`/api/clientes/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
      showToast('Datos del cliente actualizados y re-encriptados con AES-256.', 'success');
    } else {
      await apiFetch('/api/clientes', { method: 'POST', body: JSON.stringify(payload) });
      showToast('Cliente registrado con RFC y Dirección encriptados en BD.', 'success');
    }
    closeClienteModal();
    loadClientes();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteCliente(id) {
  try {
    await apiFetch(`/api/clientes/${id}`, { method: 'DELETE' });
    showToast('Cliente eliminado.', 'success');
    loadClientes();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// DASHBOARD DE ADMINISTRACIÓN: GESTIÓN DE USUARIOS Y ASIGNACIÓN DE ROLES
// ============================================================================
async function loadAdminUsers() {
  try {
    const [usersRes, rolesRes] = await Promise.all([
      apiFetch('/api/admin/users'),
      apiFetch('/api/admin/roles')
    ]);
    cachedRolesData = rolesRes.roles;
    const tbody = document.getElementById('admin-users-tbody');

    tbody.innerHTML = usersRes.users.map(u => {
      const userRoleIds = u.roles.map(r => r.id);
      const roleCheckboxes = cachedRolesData.map(r => `
        <label style="display:inline-flex; align-items:center; gap:5px; margin-right:10px; font-size:12px; cursor:pointer;">
          <input type="checkbox" class="user-role-chk-${u.id}" value="${r.id}" ${userRoleIds.includes(r.id) ? 'checked' : ''} />
          <span>${r.nombre}</span>
        </label>
      `).join('');

      return `
        <tr>
          <td>
            <strong>#${u.id} - ${u.nombre}</strong><br/>
            <span style="font-size:12px; color:#38bdf8;">${u.email}</span>
          </td>
          <td>
            <div>RFC: <strong style="color:#34d399;">${u.rfc}</strong></div>
            <div style="font-size:12px; color:var(--text-secondary);">${u.direccion}</div>
          </td>
          <td>${roleCheckboxes}</td>
          <td>
            <label style="font-size:12px; display:flex; align-items:center; gap:5px;">
              <input type="checkbox" id="user-active-${u.id}" ${u.is_active ? 'checked' : ''} />
              <span>${u.is_active ? 'Activo' : 'Bloqueado'}</span>
            </label>
          </td>
          <td>
            <div style="display:flex; gap:6px;">
              <button class="btn btn-primary btn-sm" onclick="saveUserRoles(${u.id})">Guardar Roles</button>
              ${u.id !== currentUser.id ? `<button class="btn btn-danger btn-sm" onclick="deleteUserAccount(${u.id})">Eliminar</button>` : ''}
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function saveUserRoles(userId) {
  try {
    const checks = document.querySelectorAll(`.user-role-chk-${userId}:checked`);
    const roleIds = Array.from(checks).map(c => Number(c.value));
    const isActive = document.getElementById(`user-active-${userId}`).checked;

    const res = await apiFetch(`/api/admin/users/${userId}/roles`, {
      method: 'PUT',
      body: JSON.stringify({ roleIds, is_active: isActive })
    });
    showToast(res.message, 'success');
    if (userId === currentUser.id) {
      await reloadCurrentUserProfile();
    } else {
      loadAdminUsers();
    }
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteUserAccount(userId) {
  try {
    const res = await apiFetch(`/api/admin/users/${userId}`, { method: 'DELETE' });
    showToast(res.message, 'success');
    loadAdminUsers();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// DASHBOARD DE ADMINISTRACIÓN: GESTIÓN DE ROLES Y MATRIZ DINÁMICA DE PERMISOS
// ============================================================================
async function loadAdminRoles() {
  try {
    const res = await apiFetch('/api/admin/roles');
    cachedRolesData = res.roles;
    cachedPermissionsData = res.permissions;

    // Agrupar permisos por área de la aplicación
    const areasMap = {};
    for (const p of cachedPermissionsData) {
      if (!areasMap[p.area]) areasMap[p.area] = [];
      areasMap[p.area].push(p);
    }

    const container = document.getElementById('roles-matrix-container');
    container.innerHTML = cachedRolesData.map(role => {
      const areaBlocks = Object.keys(areasMap).map(areaName => {
        const permsInArea = areasMap[areaName];
        const checksHtml = permsInArea.map(p => `
          <label class="perm-check-label">
            <input type="checkbox" class="role-perm-chk-${role.id}" value="${p.id}" ${role.permissionIds.includes(p.id) ? 'checked' : ''} />
            <span><strong>[${p.accion}]</strong> ${p.nombre}</span>
          </label>
        `).join('');

        return `
          <div class="perm-area-group">
            <div class="perm-area-title">${areaName}</div>
            ${checksHtml}
          </div>
        `;
      }).join('');

      return `
        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:8px;">
            <div>
              <h3 style="font-size:16px; color:#38bdf8;">${role.nombre}</h3>
              <span style="font-size:11px; color:var(--text-secondary);">
                ${role.is_system ? 'Rol Predeterminado del Sistema' : 'Rol Personalizado'} • ${role.userCount} usuario(s)
              </span>
            </div>
            ${!role.is_system ? `<button class="btn btn-danger btn-sm" onclick="deleteRole(${role.id})">Eliminar Rol</button>` : ''}
          </div>
          <p style="font-size:12.5px; color:var(--text-secondary); margin-bottom:12px;">${role.descripcion}</p>
          ${areaBlocks}
          <button class="btn btn-success btn-block" onclick="saveRolePermissions(${role.id})">
            Guardar Permisos de "${role.nombre}"
          </button>
        </div>
      `;
    }).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleCreateRole(e) {
  e.preventDefault();
  try {
    const nombre = document.getElementById('new-role-name').value.trim();
    const descripcion = document.getElementById('new-role-desc').value.trim();

    const res = await apiFetch('/api/admin/roles', {
      method: 'POST',
      body: JSON.stringify({ nombre, descripcion, permissionIds: [1, 4] })
    });

    showToast(res.message, 'success');
    document.getElementById('new-role-name').value = '';
    document.getElementById('new-role-desc').value = '';
    loadAdminRoles();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function saveRolePermissions(roleId) {
  try {
    const checks = document.querySelectorAll(`.role-perm-chk-${roleId}:checked`);
    const permissionIds = Array.from(checks).map(c => Number(c.value));

    const res = await apiFetch(`/api/admin/roles/${roleId}/permissions`, {
      method: 'PUT',
      body: JSON.stringify({ permissionIds })
    });
    showToast(res.message, 'success');
    await reloadCurrentUserProfile();
    showSection('sec-roles');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function deleteRole(roleId) {
  try {
    const res = await apiFetch(`/api/admin/roles/${roleId}`, { method: 'DELETE' });
    showToast(res.message, 'success');
    loadAdminRoles();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// BITÁCORAS DE AUDITORÍA, HISTORIAL DE ACCESOS E INSPECTOR CRIPTOGRÁFICO
// ============================================================================
function switchLogTab(tab) {
  document.getElementById('tab-btn-audit').classList.toggle('active', tab === 'audit');
  document.getElementById('tab-btn-access').classList.toggle('active', tab === 'access');
  document.getElementById('tab-btn-crypto').classList.toggle('active', tab === 'crypto');

  document.getElementById('subtab-audit').classList.toggle('hidden', tab !== 'audit');
  document.getElementById('subtab-access').classList.toggle('hidden', tab !== 'access');
  document.getElementById('subtab-crypto').classList.toggle('hidden', tab !== 'crypto');
}

async function loadAuditAndAccessLogs() {
  try {
    const res = await apiFetch('/api/admin/logs');

    document.getElementById('audit-logs-tbody').innerHTML = res.auditLogs.map(log => `
      <tr>
        <td style="white-space:nowrap;">${log.created_at}</td>
        <td>
          <strong>${log.usuario_nombre}</strong><br/>
          <span class="role-badge">${log.rol_activo}</span>
        </td>
        <td>${log.area}</td>
        <td><strong style="color:#38bdf8;">${log.accion}</strong></td>
        <td>${log.descripcion}</td>
        <td><code>${log.ip_address}</code></td>
      </tr>
    `).join('');

    document.getElementById('access-logs-tbody').innerHTML = res.accessLogs.map(acc => {
      let badgeColor = '#34d399';
      if (acc.evento.includes('FAILED') || acc.evento.includes('DENIED') || acc.evento.includes('BLOCKED')) {
        badgeColor = '#f87171';
      }
      return `
        <tr>
          <td style="white-space:nowrap;">${acc.created_at}</td>
          <td><strong style="color:${badgeColor};">${acc.evento}</strong></td>
          <td>${acc.usuario_nombre} (${acc.email_attempt})</td>
          <td><code>${acc.ip_address}</code></td>
          <td>${acc.detalles}</td>
        </tr>
      `;
    }).join('');

    document.getElementById('inspector-users-tbody').innerHTML = res.encryptionInspector.users.map(u => `
      <tr>
        <td>
          <strong>${u.nombre}</strong><br/>
          <span style="font-size:11px; color:var(--text-secondary);">${u.email}</span>
        </td>
        <td><span class="cipher-code">${u.password_hash}</span></td>
        <td>
          <div style="font-size:11px; color:#94a3b8;">Desencriptado: <strong style="color:#fff;">${u.rfc_decrypted}</strong></div>
          <span class="cipher-code">${u.rfc_encrypted}</span>
        </td>
        <td>
          <div style="font-size:11px; color:#94a3b8;">Desencriptado: <strong style="color:#fff;">${u.direccion_decrypted}</strong></div>
          <span class="cipher-code">${u.direccion_encrypted}</span>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// RESPALDOS AUTOMÁTICOS CADA 24 HORAS (LOCALIDAD EXTERNA USB / DISCO)
// ============================================================================
async function loadBackups() {
  try {
    const res = await apiFetch('/api/admin/backups');
    document.getElementById('backup-external-path').value = res.externalPath;

    const drivesBox = document.getElementById('detected-drives-box');
    if (res.drives && res.drives.length > 0) {
      drivesBox.innerHTML = res.drives.map(d => `
        <button type="button" class="btn btn-secondary btn-sm" onclick="document.getElementById('backup-external-path').value='${d.suggestedPath.replace(/\\/g, '\\\\')}'">
          ${d.drive} (${d.type} - ${d.label})
        </button>
      `).join('');
    } else {
      drivesBox.innerHTML = '<span style="font-size:12px; color:var(--text-secondary);">Puedes escribir cualquier ruta de unidad USB o carpeta compartida.</span>';
    }

    document.getElementById('backups-tbody').innerHTML = res.backups.map(b => `
      <tr>
        <td style="white-space:nowrap;">${b.created_at}</td>
        <td><strong>${b.filename}</strong><br/><span style="font-size:11px; color:#34d399;">AES-256-GCM (${b.size_bytes} bytes)</span></td>
        <td><span class="role-badge">${b.tipo}</span></td>
        <td><code style="font-size:11.5px; color:#38bdf8;">${b.external_path}</code><br/><span style="font-size:11px; color:var(--text-secondary);">${b.estado}</span></td>
        <td><span class="cipher-code">${b.sha256_hash.slice(0, 28)}...</span></td>
        <td>
          <a class="btn btn-secondary btn-sm" href="/api/admin/backups/${b.id}/download?token=${authToken}" target="_blank">Descargar</a>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleRunManualBackup() {
  try {
    const customExternalPath = document.getElementById('backup-external-path').value.trim();
    const res = await apiFetch('/api/admin/backups/run', {
      method: 'POST',
      body: JSON.stringify({ customExternalPath })
    });
    showToast(res.message, 'success');
    loadBackups();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

// ============================================================================
// MI PERFIL, CAMBIO DE CONTRASEÑA EN SESIÓN ABIERTA Y 2FA
// ============================================================================
async function handleChangePassword(e) {
  e.preventDefault();
  try {
    const currentPassword = await encryptForNetwork(document.getElementById('chg-current-pass').value);
    const newPassword = await encryptForNetwork(document.getElementById('chg-new-pass').value);

    const res = await apiFetch('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword })
    });

    showToast(res.message, 'success');
    document.getElementById('chg-current-pass').value = '';
    document.getElementById('chg-new-pass').value = '';
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function handleUpdateProfile(e) {
  e.preventDefault();
  try {
    const payload = {
      nombre: document.getElementById('prof-nombre').value.trim(),
      rfc: await encryptForNetwork(document.getElementById('prof-rfc').value.trim().toUpperCase()),
      direccion: await encryptForNetwork(document.getElementById('prof-direccion').value.trim()),
      telefono: await encryptForNetwork(document.getElementById('prof-telefono').value.trim()),
      totp_enabled: document.getElementById('prof-2fa-enabled').checked
    };

    const res = await apiFetch('/api/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(payload)
    });

    showToast(res.message, 'success');
    await reloadCurrentUserProfile();
    showSection('sec-perfil');
  } catch (err) {
    showToast(err.message, 'error');
  }
}
