-- =====================================================================
-- SACM v2 - Esquema inicial
-- MySQL 8 · InnoDB · utf8mb4
-- =====================================================================

-- ---------------------------------------------------------------------
-- Seguridad y usuarios
-- ---------------------------------------------------------------------

CREATE TABLE roles (
    id          TINYINT UNSIGNED PRIMARY KEY,
    code        VARCHAR(20)  NOT NULL UNIQUE,
    name        VARCHAR(50)  NOT NULL,
    description VARCHAR(255) NOT NULL,
    level       TINYINT UNSIGNED NOT NULL COMMENT 'Mayor nivel = más privilegios'
) ENGINE=InnoDB;

CREATE TABLE users (
    id                    CHAR(36)     PRIMARY KEY,
    role_id               TINYINT UNSIGNED NOT NULL,
    full_name             VARCHAR(100) NOT NULL,
    email                 VARCHAR(150) NOT NULL UNIQUE,
    password_hash         VARCHAR(255) NOT NULL,
    status                ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
    failed_login_attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
    locked_until          DATETIME NULL,
    last_login_at         DATETIME NULL,
    password_changed_at   DATETIME NULL,
    created_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles(id),
    INDEX idx_users_role (role_id),
    INDEX idx_users_status (status)
) ENGINE=InnoDB;

CREATE TABLE user_profiles (
    user_id     CHAR(36) PRIMARY KEY,
    job_title   VARCHAR(100) NULL,
    department  VARCHAR(100) NULL,
    phone       VARCHAR(30)  NULL,
    location    VARCHAR(100) NULL,
    bio         VARCHAR(500) NULL,
    avatar_file VARCHAR(100) NULL COMMENT 'Nombre del archivo en storage/avatars',
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_profiles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Muestras y análisis
-- ---------------------------------------------------------------------

-- Cada archivo único (por SHA-256) se guarda una sola vez
CREATE TABLE samples (
    id            CHAR(36)     PRIMARY KEY,
    sha256        CHAR(64)     NOT NULL UNIQUE,
    sha1          CHAR(40)     NOT NULL,
    md5           CHAR(32)     NOT NULL,
    size_bytes    BIGINT UNSIGNED NOT NULL,
    mime_type     VARCHAR(100) NULL,
    detected_type VARCHAR(50)  NOT NULL DEFAULT 'unknown',
    entropy       DECIMAL(5,3) NULL,
    first_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_samples_md5 (md5),
    INDEX idx_samples_sha1 (sha1),
    INDEX idx_samples_type (detected_type)
) ENGINE=InnoDB;

CREATE TABLE analyses (
    id               CHAR(36)     PRIMARY KEY,
    sample_id        CHAR(36)     NOT NULL,
    submitted_by     CHAR(36)     NULL,
    original_name    VARCHAR(255) NOT NULL,
    status           ENUM('queued', 'running', 'completed', 'failed') NOT NULL DEFAULT 'queued',
    verdict          ENUM('pending', 'clean', 'suspicious', 'malicious') NOT NULL DEFAULT 'pending',
    risk_score       TINYINT UNSIGNED NOT NULL DEFAULT 0,
    confidence       TINYINT UNSIGNED NOT NULL DEFAULT 0,
    threat_family    VARCHAR(100) NULL,
    threat_category  VARCHAR(50)  NULL,
    score_breakdown  JSON NULL COMMENT 'Razones que explican el puntaje',
    static_report    JSON NULL COMMENT 'Tipo real, entropía, PE, cadenas',
    reviewed_verdict ENUM('clean', 'suspicious', 'malicious') NULL COMMENT 'Último veredicto de un analista',
    reviewed_at      DATETIME NULL,
    error_message    VARCHAR(500) NULL,
    submitted_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at       DATETIME NULL,
    completed_at     DATETIME NULL,

    CONSTRAINT fk_analyses_sample FOREIGN KEY (sample_id) REFERENCES samples(id),
    CONSTRAINT fk_analyses_user FOREIGN KEY (submitted_by) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_analyses_submitted (submitted_at),
    INDEX idx_analyses_verdict (verdict, submitted_at),
    INDEX idx_analyses_user (submitted_by, submitted_at),
    INDEX idx_analyses_status (status),
    INDEX idx_analyses_family (threat_family)
) ENGINE=InnoDB;

-- Resultado de cada motor: reglas locales, VirusTotal, MalwareBazaar, CIRCL, URLhaus...
CREATE TABLE engine_results (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    analysis_id  CHAR(36)    NOT NULL,
    engine       VARCHAR(40) NOT NULL,
    status       ENUM('ok', 'not_found', 'skipped', 'error') NOT NULL,
    verdict      ENUM('clean', 'suspicious', 'malicious', 'unknown') NOT NULL DEFAULT 'unknown',
    score        TINYINT UNSIGNED NULL,
    detections   SMALLINT UNSIGNED NULL,
    total        SMALLINT UNSIGNED NULL,
    summary      VARCHAR(255) NULL,
    permalink    VARCHAR(500) NULL,
    details      JSON NULL,
    duration_ms  INT UNSIGNED NULL,
    created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_engine_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    INDEX idx_engine_analysis (analysis_id),
    INDEX idx_engine_name (engine, status)
) ENGINE=InnoDB;

-- Indicadores de compromiso extraídos del archivo
CREATE TABLE indicators (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    analysis_id  CHAR(36) NOT NULL,
    type         ENUM('url', 'domain', 'ipv4', 'email', 'registry', 'path', 'bitcoin') NOT NULL,
    value        VARCHAR(500) NOT NULL,
    is_malicious BOOLEAN NOT NULL DEFAULT FALSE,
    source       VARCHAR(40) NULL COMMENT 'Fuente que lo marcó como malicioso',

    CONSTRAINT fk_ioc_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    INDEX idx_ioc_analysis (analysis_id),
    INDEX idx_ioc_type_value (type, value(100))
) ENGINE=InnoDB;

-- Catálogo MITRE ATT&CK (solo las técnicas que detectan las reglas)
CREATE TABLE mitre_techniques (
    id     VARCHAR(12)  PRIMARY KEY COMMENT 'Ej: T1059.001',
    name   VARCHAR(150) NOT NULL,
    tactic VARCHAR(50)  NOT NULL
) ENGINE=InnoDB;

CREATE TABLE rule_matches (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    analysis_id CHAR(36)    NOT NULL,
    rule_id     VARCHAR(60) NOT NULL,
    rule_name   VARCHAR(150) NOT NULL,
    severity    ENUM('low', 'medium', 'high', 'critical') NOT NULL,
    category    VARCHAR(50) NOT NULL,
    evidence    JSON NULL,

    CONSTRAINT fk_rules_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    INDEX idx_rules_analysis (analysis_id),
    INDEX idx_rules_rule (rule_id)
) ENGINE=InnoDB;

CREATE TABLE analysis_techniques (
    analysis_id  CHAR(36)    NOT NULL,
    technique_id VARCHAR(12) NOT NULL,

    PRIMARY KEY (analysis_id, technique_id),
    CONSTRAINT fk_at_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    CONSTRAINT fk_at_technique FOREIGN KEY (technique_id) REFERENCES mitre_techniques(id),
    INDEX idx_at_technique (technique_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Trabajo del analista
-- ---------------------------------------------------------------------

CREATE TABLE analysis_reviews (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    analysis_id CHAR(36) NOT NULL,
    analyst_id  CHAR(36) NULL,
    verdict     ENUM('clean', 'suspicious', 'malicious') NOT NULL,
    notes       VARCHAR(2000) NOT NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_reviews_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    CONSTRAINT fk_reviews_analyst FOREIGN KEY (analyst_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_reviews_analysis (analysis_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE cases (
    id          CHAR(36)     PRIMARY KEY,
    code        VARCHAR(20)  NOT NULL UNIQUE COMMENT 'Ej: CASE-2026-0001',
    title       VARCHAR(150) NOT NULL,
    description VARCHAR(2000) NULL,
    status      ENUM('open', 'investigating', 'contained', 'closed') NOT NULL DEFAULT 'open',
    priority    ENUM('low', 'medium', 'high', 'critical') NOT NULL DEFAULT 'medium',
    created_by  CHAR(36) NULL,
    assigned_to CHAR(36) NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    closed_at   DATETIME NULL,

    CONSTRAINT fk_cases_creator FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
    CONSTRAINT fk_cases_assignee FOREIGN KEY (assigned_to) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_cases_status (status, priority),
    INDEX idx_cases_assignee (assigned_to)
) ENGINE=InnoDB;

CREATE TABLE case_analyses (
    case_id     CHAR(36) NOT NULL,
    analysis_id CHAR(36) NOT NULL,
    added_by    CHAR(36) NULL,
    added_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (case_id, analysis_id),
    CONSTRAINT fk_ca_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    CONSTRAINT fk_ca_analysis FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    CONSTRAINT fk_ca_user FOREIGN KEY (added_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE case_notes (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    case_id    CHAR(36) NOT NULL,
    author_id  CHAR(36) NULL,
    body       VARCHAR(4000) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_notes_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE,
    CONSTRAINT fk_notes_author FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_notes_case (case_id, created_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Auditoría
-- ---------------------------------------------------------------------

CREATE TABLE audit_logs (
    id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id     CHAR(36)    NULL,
    action      VARCHAR(60) NOT NULL,
    entity_type VARCHAR(40) NULL,
    entity_id   VARCHAR(64) NULL,
    ip_address  VARCHAR(45) NULL,
    user_agent  VARCHAR(255) NULL,
    metadata    JSON NULL,
    created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_audit_created (created_at),
    INDEX idx_audit_user (user_id, created_at),
    INDEX idx_audit_action (action)
) ENGINE=InnoDB;
