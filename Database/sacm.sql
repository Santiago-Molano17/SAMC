CREATE DATABASE IF NOT EXISTS sacm;

USE sacm;

-- =========================
-- TABLA ROLES
-- =========================

CREATE TABLE IF NOT EXISTS roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL
);

INSERT IGNORE INTO roles (role_name) VALUES
('SUPER_ADMIN'),
('ADMIN'),
('ANALYST'),
('USER');

-- =========================
-- TABLA USUARIOS
-- =========================

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(36) PRIMARY KEY,
    fullname VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role_id INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- =========================
-- TABLA ARCHIVOS
-- =========================

CREATE TABLE IF NOT EXISTS uploads (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36),
    original_name VARCHAR(255),
    file_type VARCHAR(50),
    file_size BIGINT,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- =========================
-- TABLA ANALISIS AVANZADA
-- =========================

CREATE TABLE IF NOT EXISTS analysis (
    id VARCHAR(36) PRIMARY KEY,
    upload_id VARCHAR(36),
    
    malware_type VARCHAR(100),
    risk_level VARCHAR(50),
    risk_percentage INT DEFAULT 0,
    
    vulnerabilities TEXT,
    behavior TEXT,
    
    affected_system_areas JSON,
    detected_capabilities JSON,
    
    recommendation TEXT,
    
    analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    analyzed_by VARCHAR(36),

    FOREIGN KEY (upload_id) REFERENCES uploads(id),
    FOREIGN KEY (analyzed_by) REFERENCES users(id)
);

-- =========================
-- TABLA PERFILES DE USUARIO
-- =========================

CREATE TABLE IF NOT EXISTS user_profiles (
    id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) UNIQUE NOT NULL,
    department VARCHAR(100),
    profile_status VARCHAR(20) DEFAULT 'ACTIVE',
    last_login TIMESTAMP,
    profile_created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- =========================
-- TABLA MALWARE KNOWLEDGE BASE
-- =========================

CREATE TABLE IF NOT EXISTS malware_database (
    id VARCHAR(36) PRIMARY KEY,
    malware_name VARCHAR(100) UNIQUE NOT NULL,
    malware_type VARCHAR(50),
    severity_level VARCHAR(20),
    description TEXT,
    signatures JSON,
    behaviors JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =========================
-- TABLA HISTORIAL DE ACTIVIDADES
-- =========================

CREATE TABLE IF NOT EXISTS activity_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36),
    action_type VARCHAR(100),
    resource_type VARCHAR(50),
    resource_id VARCHAR(36),
    details JSON,
    action_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- =========================
-- TABLA LOGS (MEJORADA)
-- =========================

CREATE TABLE IF NOT EXISTS logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(36),
    user_email VARCHAR(100),
    action_type VARCHAR(100),
    action_details TEXT,
    ip_address VARCHAR(45),
    action_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- =========================
-- INSERTAR BASE DE DATOS DE MALWARE CONOCIDA
-- =========================

INSERT IGNORE INTO malware_database (id, malware_name, malware_type, severity_level, description, signatures, behaviors) VALUES

('mal-001', 'Trojan.Generic', 'Trojan', 'CRITICAL', 'Troyano genérico que modifica archivos del sistema', 
    JSON_OBJECT('extensions', JSON_ARRAY('exe', 'dll', 'sys')), 
    JSON_OBJECT('capabilities', JSON_ARRAY('modify_system_files', 'registry_manipulation', 'persistence_mechanisms'))),

('mal-002', 'Ransomware.WannaCry', 'Ransomware', 'CRITICAL', 'Ransomware que encripta archivos del usuario',
    JSON_OBJECT('extensions', JSON_ARRAY('exe', 'scr')),
    JSON_OBJECT('capabilities', JSON_ARRAY('file_encryption', 'network_propagation', 'extortion'))),

('mal-003', 'Spyware.Generic', 'Spyware', 'HIGH', 'Spyware que recopila información del usuario',
    JSON_OBJECT('extensions', JSON_ARRAY('exe', 'dll', 'vbs')),
    JSON_OBJECT('capabilities', JSON_ARRAY('keylogging', 'screen_capture', 'data_exfiltration'))),

('mal-004', 'Worm.Generic', 'Worm', 'CRITICAL', 'Gusano que se auto-propaga',
    JSON_OBJECT('extensions', JSON_ARRAY('exe', 'vbs', 'bat')),
    JSON_OBJECT('capabilities', JSON_ARRAY('self_replication', 'network_scanning', 'propagation'))),

('mal-005', 'Rootkit.Generic', 'Rootkit', 'CRITICAL', 'Rootkit que oculta procesos maliciosos',
    JSON_OBJECT('extensions', JSON_ARRAY('sys', 'exe', 'dll')),
    JSON_OBJECT('capabilities', JSON_ARRAY('kernel_access', 'process_hiding', 'persistence')));