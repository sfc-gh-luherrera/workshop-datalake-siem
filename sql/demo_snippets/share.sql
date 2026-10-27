-- =====================================================================
-- Share de IOC con otra cuenta Snowflake (CSIRT del grupo, otra filial, MSSP)
-- Sin copias ni ficheros: el consumidor consulta en vivo una vista segura.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- Vista segura: solo agregados por indicador, sin hosts internos ni usuarios.
-- SECURE oculta la definición al consumidor y es obligatoria para compartir vistas.
CREATE OR REPLACE SECURE VIEW V_IOC_HITS_SHARE
  COMMENT = 'Coincidencias con IOC agregadas por indicador para compartir'
AS
SELECT indicator, class, unit, MAX(confidence) AS confidence, COUNT(*) AS hits,
       COUNT(DISTINCT src_ip) AS hosts_afectados, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.GOLD.DET_IOC_HITS
GROUP BY indicator, class, unit;

SELECT * FROM V_IOC_HITS_SHARE ORDER BY last_seen;

-- Crear el share y conceder el acceso mínimo (requiere ACCOUNTADMIN o CREATE SHARE)
USE ROLE ACCOUNTADMIN;
CREATE SHARE IF NOT EXISTS SOC_IOC_SHARE COMMENT = 'IOC detectados por el SOC';
GRANT USAGE ON DATABASE SECURITY_LAKE TO SHARE SOC_IOC_SHARE;
GRANT USAGE ON SCHEMA SECURITY_LAKE.GOLD TO SHARE SOC_IOC_SHARE;
GRANT SELECT ON VIEW SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE TO SHARE SOC_IOC_SHARE;

SHOW SHARES LIKE 'SOC_IOC_SHARE';
SHOW GRANTS TO SHARE SOC_IOC_SHARE;

-- Añadir la cuenta consumidora (misma región; entre regiones/nubes usar un listing):
-- ALTER SHARE SOC_IOC_SHARE ADD ACCOUNTS = <ORG>.<CUENTA_CSIRT>;
-- En la cuenta consumidora:
--   CREATE DATABASE SOC_IOC FROM SHARE <ORG>.<CUENTA_PROVEEDORA>.SOC_IOC_SHARE;
--   SELECT * FROM SOC_IOC.GOLD.V_IOC_HITS_SHARE;
-- Políticas: la row access policy RAP_BY_UNIT de SILVER.NETWORK_ACTIVITY se evalúa
-- también para el consumidor; sus roles no existen aquí, así que las filas de red
-- no se verán salvo que la política contemple el share (p. ej. con
-- IS_DATABASE_ROLE_IN_SESSION o CURRENT_ACCOUNT()). Validar con la cuenta real.

-- Al terminar (también en 99_teardown.sql):
-- DROP SHARE IF EXISTS SOC_IOC_SHARE;
-- DROP VIEW IF EXISTS SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE;
