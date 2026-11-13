const crypto = require('node:crypto');

// Clave maestra de 256 bits derivada para encriptación AES-256-GCM en Base de Datos y Red
const SECRET_PASSPHRASE = process.env.APP_ENCRYPTION_KEY || 'SeguridadEnComputo_ProyectoFinal_AES256_Key_2026!';
const MASTER_KEY = crypto.scryptSync(SECRET_PASSPHRASE, 'seguridad_computo_salt_v1', 32);

// Clave compartida para cifrado de tránsito de red (E2E Payload Encryption con WebCrypto)
const NETWORK_SHARED_HEX = crypto.createHash('sha256').update(SECRET_PASSPHRASE + '_NETWORK_TLS_LAYER').digest('hex');

/**
 * Encripta un texto plano usando AES-256-GCM para almacenamiento seguro en la BD
 * Formato de salida: enc:v1:<iv_hex>:<authTag_hex>:<ciphertext_hex>
 */
function encryptField(plainText) {
  if (plainText === null || plainText === undefined || plainText === '') return '';
  const text = String(plainText);
  if (text.startsWith('enc:v1:')) return text; // Ya está encriptado
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `enc:v1:${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Desencripta un campo cifrado con AES-256-GCM desde la BD
 */
function decryptField(cipherText) {
  if (!cipherText || typeof cipherText !== 'string') return '';
  if (!cipherText.startsWith('enc:v1:')) return cipherText;
  try {
    const parts = cipherText.split(':');
    if (parts.length !== 5) return '[Formato de cifrado inválido]';
    const iv = Buffer.from(parts[2], 'hex');
    const authTag = Buffer.from(parts[3], 'hex');
    const encryptedHex = parts[4];
    const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    return '[Error al desencriptar dato]';
  }
}

/**
 * Desencripta un payload enviado por red desde el navegador (AES-256-GCM WebCrypto API)
 * Formato esperado: net:v1:<iv_hex>:<ciphertext_and_tag_hex>
 */
function decryptNetworkValue(val) {
  if (!val || typeof val !== 'string' || !val.startsWith('net:v1:')) return val;
  try {
    const parts = val.split(':');
    if (parts.length !== 4) return val;
    const iv = Buffer.from(parts[2], 'hex');
    const dataBuf = Buffer.from(parts[3], 'hex');
    // WebCrypto AES-GCM concatena los 16 bytes del authTag al final del ciphertext
    const authTag = dataBuf.subarray(dataBuf.length - 16);
    const ciphertext = dataBuf.subarray(0, dataBuf.length - 16);
    const netKey = Buffer.from(NETWORK_SHARED_HEX, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', netKey, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(ciphertext, undefined, 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    return val;
  }
}

/**
 * Middleware para desencriptar automáticamente campos sensibles que viajaron cifrados por la red
 */
function decryptNetworkPayloadMiddleware(req, res, next) {
  if (req.body && typeof req.body === 'object') {
    for (const key of Object.keys(req.body)) {
      if (typeof req.body[key] === 'string' && req.body[key].startsWith('net:v1:')) {
        req.body[`_raw_network_${key}`] = req.body[key];
        req.body[key] = decryptNetworkValue(req.body[key]);
      }
    }
  }
  next();
}

/**
 * Hash de contraseñas con algoritmo Scrypt + Salt aleatorio de 16 bytes
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${derivedKey}`;
}

/**
 * Verifica una contraseña contra su hash almacenado con comparación en tiempo constante
 */
function verifyPassword(password, storedHash) {
  if (!password || !storedHash || !storedHash.startsWith('scrypt:')) return false;
  const parts = storedHash.split(':');
  if (parts.length !== 3) return false;
  const [, salt, keyHex] = parts;
  const keyBuffer = Buffer.from(keyHex, 'hex');
  const derivedBuffer = crypto.scryptSync(password, salt, 64);
  if (keyBuffer.length !== derivedBuffer.length) return false;
  return crypto.timingSafeEqual(keyBuffer, derivedBuffer);
}

// ============================================================================
// Implementación RFC 6238 TOTP (Verificación en Dos Pasos / Google Authenticator)
// ============================================================================
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function generateBase32Secret(length = 20) {
  const bytes = crypto.randomBytes(length);
  let secret = '';
  for (let i = 0; i < bytes.length; i++) {
    secret += BASE32_ALPHABET[bytes[i] % 32];
  }
  return secret;
}

function base32ToBuffer(base32) {
  const clean = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (let i = 0; i < clean.length; i++) {
    const val = BASE32_ALPHABET.indexOf(clean[i]);
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotpToken(secretBase32, timeStepOffset = 0) {
  const key = base32ToBuffer(secretBase32);
  const epoch = Math.floor(Date.now() / 1000);
  const counter = Math.floor(epoch / 30) + timeStepOffset;
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = binary % 1000000;
  return String(otp).padStart(6, '0');
}

function verifyTotpToken(secretBase32, token) {
  if (!secretBase32 || !token) return false;
  const cleanToken = String(token).trim();
  if (!/^\d{6}$/.test(cleanToken)) return false;
  // Permite ventana de +/- 1 paso de 30 segundos por desfase de reloj
  for (let offset = -1; offset <= 1; offset++) {
    if (generateTotpToken(secretBase32, offset) === cleanToken) {
      return true;
    }
  }
  return false;
}

function generateNumericOtp(digits = 6) {
  const max = Math.pow(10, digits);
  const num = crypto.randomInt(0, max);
  return String(num).padStart(digits, '0');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

module.exports = {
  NETWORK_SHARED_HEX,
  encryptField,
  decryptField,
  decryptNetworkValue,
  decryptNetworkPayloadMiddleware,
  hashPassword,
  verifyPassword,
  generateBase32Secret,
  generateTotpToken,
  verifyTotpToken,
  generateNumericOtp,
  hashToken
};
