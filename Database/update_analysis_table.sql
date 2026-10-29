-- ========================================
-- SCRIPT DE ACTUALIZACIÓN DE TABLA ANALYSIS
-- ========================================

USE sacm;

-- Verificar y agregar columnas si faltan

-- Agregar risk_percentage si no existe
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS risk_percentage INT DEFAULT 0;

-- Agregar affected_system_areas si no existe
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS affected_system_areas JSON;

-- Agregar detected_capabilities si no existe
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS detected_capabilities JSON;

-- Agregar recommendation si no existe
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS recommendation TEXT;

-- Agregar analyzed_by si no existe
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS analyzed_by VARCHAR(36);

-- Agregar FOREIGN KEY si no existe (puede fallar si ya existe, se ignora)
ALTER TABLE analysis ADD CONSTRAINT FOREIGN KEY (analyzed_by) REFERENCES users(id);

-- ========================================
-- VERIFICAR ESTRUCTURA
-- ========================================

DESCRIBE analysis;

-- Listo, la tabla está actualizada
