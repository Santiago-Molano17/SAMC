-- =====================================================================
-- SACM v2 - Datos de referencia
-- =====================================================================

INSERT INTO roles (id, code, name, description, level) VALUES
(1, 'SUPER_ADMIN', 'Super administrador', 'Control total del sistema, integraciones y administradores', 4),
(2, 'ADMIN',       'Administrador',       'Gestiona usuarios, analistas y la auditoría', 3),
(3, 'ANALYST',     'Analista',            'Investiga amenazas, revisa veredictos, gestiona casos y analítica', 2),
(4, 'USER',        'Usuario',             'Envía archivos para análisis y consulta sus resultados', 1);

-- Técnicas MITRE ATT&CK que detectan las reglas de SACM
INSERT INTO mitre_techniques (id, name, tactic) VALUES
('T1003',     'OS Credential Dumping',                    'Credential Access'),
('T1027',     'Obfuscated Files or Information',          'Defense Evasion'),
('T1027.002', 'Software Packing',                         'Defense Evasion'),
('T1036.007', 'Double File Extension',                    'Defense Evasion'),
('T1036.008', 'Masquerade File Type',                     'Defense Evasion'),
('T1041',     'Exfiltration Over C2 Channel',             'Exfiltration'),
('T1046',     'Network Service Discovery',                'Discovery'),
('T1053.005', 'Scheduled Task',                           'Persistence'),
('T1055',     'Process Injection',                        'Defense Evasion'),
('T1056.001', 'Keylogging',                               'Collection'),
('T1059.001', 'PowerShell',                               'Execution'),
('T1059.004', 'Unix Shell',                               'Execution'),
('T1059.005', 'Visual Basic',                             'Execution'),
('T1059.007', 'JavaScript',                               'Execution'),
('T1071.001', 'Web Protocols',                            'Command and Control'),
('T1080',     'Taint Shared Content',                     'Lateral Movement'),
('T1082',     'System Information Discovery',             'Discovery'),
('T1087',     'Account Discovery',                        'Discovery'),
('T1091',     'Replication Through Removable Media',      'Lateral Movement'),
('T1102',     'Web Service',                              'Command and Control'),
('T1105',     'Ingress Tool Transfer',                    'Command and Control'),
('T1113',     'Screen Capture',                           'Collection'),
('T1204.002', 'Malicious File',                           'Execution'),
('T1218',     'System Binary Proxy Execution',            'Defense Evasion'),
('T1486',     'Data Encrypted for Impact',                'Impact'),
('T1490',     'Inhibit System Recovery',                  'Impact'),
('T1496',     'Resource Hijacking',                       'Impact'),
('T1547.001', 'Registry Run Keys / Startup Folder',       'Persistence'),
('T1555.003', 'Credentials from Web Browsers',            'Credential Access'),
('T1562.001', 'Disable or Modify Tools',                  'Defense Evasion'),
('T1622',     'Debugger Evasion',                         'Defense Evasion');
