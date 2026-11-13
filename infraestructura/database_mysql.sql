-- ============================================================================
-- SCRIPT DE BASE DE DATOS (MySQL / MariaDB) - SEGURIDAD EN CÓMPUTO
-- Aplicación con Gestión de Roles y Permisos de Usuario (RBAC)
-- ============================================================================

CREATE DATABASE IF NOT EXISTS seguridad_rbac CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE seguridad_rbac;

CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nombre VARCHAR(150) NOT NULL,
  email VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  rfc_encrypted TEXT NOT NULL,
  direccion_encrypted TEXT NOT NULL,
  telefono_encrypted TEXT,
  totp_secret_encrypted TEXT NOT NULL,
  totp_enabled TINYINT(1) DEFAULT 0,
  is_active TINYINT(1) DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS roles (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nombre VARCHAR(80) NOT NULL UNIQUE,
  descripcion VARCHAR(255) NOT NULL,
  is_system TINYINT(1) DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS permissions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  codigo VARCHAR(80) NOT NULL UNIQUE,
  area VARCHAR(100) NOT NULL,
  accion VARCHAR(50) NOT NULL,
  nombre VARCHAR(120) NOT NULL,
  descripcion VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id INT NOT NULL,
  permission_id INT NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_roles (
  user_id INT NOT NULL,
  role_id INT NOT NULL,
  assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  email_attempt VARCHAR(150) NOT NULL,
  usuario_nombre VARCHAR(150) DEFAULT '',
  evento VARCHAR(80) NOT NULL,
  ip_address VARCHAR(60) NOT NULL,
  user_agent TEXT,
  detalles TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NULL,
  usuario_nombre VARCHAR(150) NOT NULL,
  usuario_email VARCHAR(150) NOT NULL,
  rol_activo VARCHAR(100) NOT NULL,
  area VARCHAR(100) NOT NULL,
  accion VARCHAR(100) NOT NULL,
  recurso_id VARCHAR(60) DEFAULT '',
  descripcion TEXT NOT NULL,
  ip_address VARCHAR(60) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS password_resets (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT NOT NULL,
  token_hash VARCHAR(128) NOT NULL,
  metodo VARCHAR(40) NOT NULL,
  expires_at BIGINT NOT NULL,
  used TINYINT(1) DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS documentos (
  id INT AUTO_INCREMENT PRIMARY KEY,
  titulo VARCHAR(200) NOT NULL,
  categoria VARCHAR(100) NOT NULL,
  clasificacion VARCHAR(60) DEFAULT 'USO INTERNO',
  contenido TEXT NOT NULL,
  notas_confidenciales_encrypted TEXT,
  autor_id INT NULL,
  autor_nombre VARCHAR(150) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS clientes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  razon_social VARCHAR(200) NOT NULL,
  contacto_nombre VARCHAR(150) NOT NULL,
  email VARCHAR(150) NOT NULL,
  rfc_encrypted TEXT NOT NULL,
  direccion_encrypted TEXT NOT NULL,
  telefono_encrypted TEXT NOT NULL,
  contrato_monto_encrypted TEXT NOT NULL,
  creado_por VARCHAR(150) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backups (
  id INT AUTO_INCREMENT PRIMARY KEY,
  filename VARCHAR(255) NOT NULL,
  local_path TEXT NOT NULL,
  external_path TEXT NOT NULL,
  size_bytes INT NOT NULL,
  sha256_hash VARCHAR(128) NOT NULL,
  encrypted TINYINT(1) DEFAULT 1,
  tipo VARCHAR(60) NOT NULL,
  ejecutado_por VARCHAR(150) NOT NULL,
  estado VARCHAR(255) NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
