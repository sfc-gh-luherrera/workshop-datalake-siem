-- =====================================================================
-- 03 · SILVER: modelo común normalizado (estilo OCSF), calidad, linaje, ciclo de vida
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.SILVER;

-- Actividad DNS (OCSF: DNS Activity)
CREATE OR REPLACE DYNAMIC TABLE DNS_ACTIVITY TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:ts::TIMESTAMP_NTZ              AS event_time,
       raw:client_ip::STRING              AS src_ip,
       LOWER(raw:query::STRING)           AS query,
       REGEXP_SUBSTR(LOWER(raw:query::STRING), '[^.]+[.][^.]+$') AS query_domain,
       SPLIT_PART(LOWER(raw:query::STRING), '.', 1)              AS query_label,
       raw:qtype::STRING                  AS query_type,
       raw:rcode::STRING                  AS rcode,
       raw:unit::STRING                   AS unit,
       raw:country::STRING                AS country,
       source, technology, src_file
FROM SECURITY_LAKE.BRONZE.DNS_RAW;

-- Actividad de red: NetFlow + firewall/VPN syslog parseado (OCSF: Network Activity)
CREATE OR REPLACE DYNAMIC TABLE NETWORK_ACTIVITY TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:ts::TIMESTAMP_NTZ AS event_time, raw:src_ip::STRING AS src_ip, raw:dst_ip::STRING AS dst_ip,
       raw:dst_port::INT AS dst_port, raw:proto::STRING AS proto, raw:bytes::NUMBER AS bytes_out,
       NULL::STRING AS action, NULL::STRING AS user_name, NULL::STRING AS device,
       raw:unit::STRING AS unit, raw:country::STRING AS country, source, technology, src_file
FROM SECURITY_LAKE.BRONZE.NETFLOW_RAW
UNION ALL
SELECT TRY_TO_TIMESTAMP_NTZ(REGEXP_SUBSTR(raw_line, '^<[0-9]+>(\\S+)', 1, 1, 'e', 1)),
       REGEXP_SUBSTR(raw_line, 'src=(\\S+)', 1, 1, 'e', 1),
       REGEXP_SUBSTR(raw_line, 'dst=(\\S+)', 1, 1, 'e', 1),
       TRY_TO_NUMBER(REGEXP_SUBSTR(raw_line, 'dport=(\\S+)', 1, 1, 'e', 1)),
       UPPER(REGEXP_SUBSTR(raw_line, 'proto=(\\S+)', 1, 1, 'e', 1)),
       NULL,
       REGEXP_SUBSTR(raw_line, 'action=(\\S+)', 1, 1, 'e', 1),
       REGEXP_SUBSTR(raw_line, 'user=(\\S+)', 1, 1, 'e', 1),
       REGEXP_SUBSTR(raw_line, '^<[0-9]+>\\S+ (\\S+)', 1, 1, 'e', 1),
       'UES', 'ES', source, REGEXP_SUBSTR(raw_line, 'vendor=(\\S+)', 1, 1, 'e', 1), src_file
FROM SECURITY_LAKE.BRONZE.FW_RAW;

-- Autenticación: Windows/AD + Office 365 (OCSF: Authentication / API Activity)
CREATE OR REPLACE DYNAMIC TABLE AUTH_ACTIVITY TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:TimeCreated::TIMESTAMP_NTZ AS event_time, raw:TargetUserName::STRING AS user_name,
       raw:IpAddress::STRING AS src_ip, raw:Computer::STRING AS device, raw:EventID::INT AS event_id,
       CASE raw:EventID::INT WHEN 4624 THEN 'logon_success' WHEN 4625 THEN 'logon_failure'
            WHEN 4672 THEN 'special_privileges' ELSE 'other' END AS activity,
       raw:unit::STRING AS unit, raw:country::STRING AS country, source, technology, src_file
FROM SECURITY_LAKE.BRONZE.AD_RAW
UNION ALL
SELECT raw:CreationTime::TIMESTAMP_NTZ, SPLIT_PART(raw:UserId::STRING, '@', 1), raw:ClientIP::STRING,
       raw:Workload::STRING, NULL, raw:Operation::STRING, raw:unit::STRING, raw:country::STRING,
       source, technology, src_file
FROM SECURITY_LAKE.BRONZE.O365_RAW;

-- Hallazgos IDS: Suricata EVE (OCSF: Detection Finding)
CREATE OR REPLACE DYNAMIC TABLE IDS_FINDINGS TARGET_LAG = '1 hour' WAREHOUSE = SOC_WH AS
SELECT raw:timestamp::TIMESTAMP_NTZ AS event_time, raw:src_ip::STRING AS src_ip, raw:dest_ip::STRING AS dst_ip,
       raw:dest_port::INT AS dst_port, raw:alert.signature::STRING AS signature,
       raw:alert.signature_id::INT AS signature_id, raw:alert.severity::INT AS severity,
       raw:alert.category::STRING AS category, raw:unit::STRING AS unit, raw:country::STRING AS country,
       source, technology, src_file
FROM SECURITY_LAKE.BRONZE.SURICATA_RAW;

-- Vista unificada para búsquedas transversales (4.4)
CREATE OR REPLACE VIEW ALL_EVENTS AS
SELECT event_time, 'dns' AS class, src_ip, NULL AS dst_ip, NULL AS user_name, query AS detail, unit, country, source FROM DNS_ACTIVITY
UNION ALL SELECT event_time, 'network', src_ip, dst_ip, user_name, action, unit, country, source FROM NETWORK_ACTIVITY
UNION ALL SELECT event_time, 'auth', src_ip, NULL, user_name, activity, unit, country, source FROM AUTH_ACTIVITY
UNION ALL SELECT event_time, 'ids', src_ip, dst_ip, NULL, signature, unit, country, source FROM IDS_FINDINGS;

-- ---------------------------------------------------------------------
-- Calidad del dato (3.4): DMF nativas sobre la capa normalizada
-- ---------------------------------------------------------------------
ALTER DYNAMIC TABLE NETWORK_ACTIVITY SET DATA_METRIC_SCHEDULE = 'TRIGGER_ON_CHANGES';
ALTER DYNAMIC TABLE NETWORK_ACTIVITY ADD DATA METRIC FUNCTION SNOWFLAKE.CORE.NULL_COUNT ON (src_ip);
ALTER DYNAMIC TABLE NETWORK_ACTIVITY ADD DATA METRIC FUNCTION SNOWFLAKE.CORE.NULL_COUNT ON (event_time);
-- Comprobación ad hoc en directo:
SELECT SNOWFLAKE.CORE.NULL_COUNT(SELECT event_time FROM NETWORK_ACTIVITY) AS null_event_time;

-- ---------------------------------------------------------------------
-- Reproceso histórico (3.5): cambia el parser y recalcula todo el histórico
-- Demo: añade un campo a DNS_ACTIVITY (CREATE OR REPLACE) o fuerza refresco:
-- ---------------------------------------------------------------------
ALTER DYNAMIC TABLE DNS_ACTIVITY REFRESH;

-- Linaje (3.6): Snowsight > Catalog > SILVER.NETWORK_ACTIVITY > Lineage

-- ---------------------------------------------------------------------
-- Niveles de almacenamiento y retención (2.1, 2.5, 2.8)
-- Archiva a COOL las filas de más de 365 días y las expira tras 5 años en archivo.
-- AVISO: el tier de archivo de una tabla es permanente. Se aplica a BRONZE.
-- ---------------------------------------------------------------------
USE SCHEMA SECURITY_LAKE.BRONZE;
CREATE STORAGE LIFECYCLE POLICY IF NOT EXISTS SLP_RAW_1Y_COOL
  AS (ts TIMESTAMP_LTZ) RETURNS BOOLEAN -> ts < DATEADD('day', -365, CURRENT_TIMESTAMP())
  ARCHIVE_TIER = COOL
  ARCHIVE_FOR_DAYS = 1825
  COMMENT = 'Raw: 1 año consultable, 5 años en archivo COOL';
ALTER TABLE DNS_RAW ADD STORAGE LIFECYCLE POLICY SLP_RAW_1Y_COOL ON (file_ts);
SHOW STORAGE LIFECYCLE POLICIES IN SCHEMA SECURITY_LAKE.BRONZE;

-- Variante COLD (no ejecutar sobre DNS_RAW: ya tiene tier COOL y el tier no se cambia).
-- COLD: ~1/4 del coste de COOL, mínimo 180 días en archivo, solo AWS y GCP,
-- recuperación de hasta 48 h. Para fuentes que casi nunca se consultan (p. ej. NetFlow).
-- CREATE STORAGE LIFECYCLE POLICY IF NOT EXISTS SLP_RAW_90D_COLD
--   AS (ts TIMESTAMP_LTZ) RETURNS BOOLEAN -> ts < DATEADD('day', -90, CURRENT_TIMESTAMP())
--   ARCHIVE_TIER = COLD
--   ARCHIVE_FOR_DAYS = 2555
--   COMMENT = 'Raw: 90 días consultable, 7 años en archivo COLD';
-- ALTER TABLE NETFLOW_RAW ADD STORAGE LIFECYCLE POLICY SLP_RAW_90D_COLD ON (file_ts);
-- Lo archivado no se consulta directamente: se recupera a una tabla nueva (WHERE obligatorio).
-- Estimar antes el coste con EXPLAIN y ver metadatos sin coste:
-- SELECT SYSTEM$GET_TABLE_ARCHIVE_METADATA('SECURITY_LAKE.BRONZE.NETFLOW_RAW');
-- EXPLAIN CREATE TABLE NETFLOW_2025_Q4 FROM ARCHIVE OF NETFLOW_RAW AS a
--   WHERE a.file_ts BETWEEN '2025-10-01' AND '2025-12-31';
-- Desde COLD la restauración puede tardar hasta 48 h: ajustar la sesión antes.
-- ALTER SESSION SET STATEMENT_TIMEOUT_IN_SECONDS = 172800, ABORT_DETACHED_QUERY = FALSE;
-- CREATE TABLE NETFLOW_2025_Q4 FROM ARCHIVE OF NETFLOW_RAW AS a
--   WHERE a.file_ts BETWEEN '2025-10-01' AND '2025-12-31';
