-- =====================================================================
-- 08 · Gobierno: etiquetas, enmascaramiento, segregación por unidad, auditoría, consumo
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
CREATE SCHEMA IF NOT EXISTS SECURITY_LAKE.GOVERNANCE;
USE SCHEMA SECURITY_LAKE.GOVERNANCE;

-- 1) Clasificación con etiquetas
CREATE TAG IF NOT EXISTS DATA_SENSITIVITY ALLOWED_VALUES 'PII', 'CONFIDENTIAL', 'INTERNAL';
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.AUTH_ACTIVITY MODIFY COLUMN user_name SET TAG DATA_SENSITIVITY = 'PII';
ALTER TABLE SECURITY_LAKE.BRONZE.SIM_REQUESTS MODIFY COLUMN msisdn SET TAG DATA_SENSITIVITY = 'PII';
-- SIM_SCORED es una copia (CREATE TABLE AS en 06): no hereda la política de SIM_REQUESTS.
-- Si se vuelve a ejecutar 06, hay que volver a ejecutar este bloque.
ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET TAG DATA_SENSITIVITY = 'PII';

-- 2) Enmascaramiento con hash determinista: el analista no ve el dato, pero puede correlacionar
CREATE OR REPLACE MASKING POLICY MASK_PII_HASH AS (val STRING) RETURNS STRING ->
  CASE WHEN IS_ROLE_IN_SESSION('THREAT_HUNTER') THEN val
       ELSE 'h_' || LEFT(SHA2(val), 16) END;
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.AUTH_ACTIVITY MODIFY COLUMN user_name SET MASKING POLICY MASK_PII_HASH;
ALTER TABLE SECURITY_LAKE.BRONZE.SIM_REQUESTS MODIFY COLUMN msisdn SET MASKING POLICY MASK_PII_HASH;
ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET MASKING POLICY MASK_PII_HASH;

-- 3) Segregación por unidad de negocio en un único tenant (10.5)
CREATE TABLE IF NOT EXISTS UNIT_ACCESS (role_name STRING, unit STRING);
INSERT INTO UNIT_ACCESS
  SELECT * FROM VALUES ('SOC_ANALYST', 'UES') v
  WHERE NOT EXISTS (SELECT 1 FROM UNIT_ACCESS);
CREATE OR REPLACE ROW ACCESS POLICY RAP_BY_UNIT AS (row_unit STRING) RETURNS BOOLEAN ->
  IS_ROLE_IN_SESSION('THREAT_HUNTER')
  OR EXISTS (SELECT 1 FROM SECURITY_LAKE.GOVERNANCE.UNIT_ACCESS m
             WHERE IS_ROLE_IN_SESSION(m.role_name) AND m.unit = row_unit);
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.NETWORK_ACTIVITY ADD ROW ACCESS POLICY RAP_BY_UNIT ON (unit);

-- Demo: mismo SELECT, distinto resultado según el rol.
-- IMPORTANTE: desactivar roles secundarios; si no, el usuario hereda THREAT_HUNTER y lo ve todo.
USE ROLE SOC_ANALYST;
USE SECONDARY ROLES NONE;
SELECT unit, COUNT(*) FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY unit;        -- solo UES
SELECT user_name, COUNT(*) FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY
WHERE activity = 'logon_failure' GROUP BY 1 ORDER BY 2 DESC LIMIT 3;                    -- hash
USE ROLE THREAT_HUNTER;
SELECT unit, COUNT(*) FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY unit;        -- todas
SELECT user_name, COUNT(*) FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY
WHERE activity = 'logon_failure' GROUP BY 1 ORDER BY 2 DESC LIMIT 3;                    -- en claro
-- El agente SOC (07) respeta estas mismas políticas: preguntarle como SOC_ANALYST (8.7)

-- 4) Auditoría (10.4, 9.11): quién accedió a datos PII y qué cambió (latencia ~1-3 h)
USE ROLE SOC_ADMIN;
SELECT ah.query_start_time, ah.user_name, obj.value:objectName::STRING AS object_name,
       col.value:columnName::STRING AS column_name
FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY ah,
     LATERAL FLATTEN(ah.base_objects_accessed) obj,
     LATERAL FLATTEN(obj.value:columns, OUTER => TRUE) col
WHERE ah.query_start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND obj.value:objectName::STRING ILIKE 'SECURITY_LAKE.%'
  AND col.value:columnName::STRING IN ('USER_NAME', 'MSISDN')
ORDER BY ah.query_start_time DESC LIMIT 50;

SELECT start_time, user_name, role_name, query_type, LEFT(query_text, 100) AS query_text
FROM SNOWFLAKE.ACCOUNT_USAGE.QUERY_HISTORY
WHERE start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
  AND query_type IN ('ALTER_TABLE_MODIFY_COLUMN', 'CREATE_MASKING_POLICY', 'CREATE_ROW_ACCESS_POLICY', 'GRANT', 'REVOKE')
ORDER BY start_time DESC LIMIT 50;

-- Accesos a la plataforma (Trust Center complementa con escáneres de seguridad)
SELECT event_timestamp, user_name, client_ip, first_authentication_factor, is_success, error_message
FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
WHERE event_timestamp >= DATEADD('day', -7, CURRENT_TIMESTAMP())
ORDER BY event_timestamp DESC LIMIT 20;

-- 5) Control de consumo (9.8): monitor de créditos con aviso y suspensión
USE ROLE ACCOUNTADMIN;
CREATE RESOURCE MONITOR IF NOT EXISTS SOC_MONITOR WITH CREDIT_QUOTA = 50
  FREQUENCY = MONTHLY START_TIMESTAMP = IMMEDIATELY
  TRIGGERS ON 80 PERCENT DO NOTIFY ON 100 PERCENT DO SUSPEND;
ALTER WAREHOUSE SOC_WH SET RESOURCE_MONITOR = SOC_MONITOR;
