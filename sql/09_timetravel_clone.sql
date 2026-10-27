-- =====================================================================
-- 09 · Zero-Copy Clone y Time Travel en el día a día del SOC
-- Todo lo destructivo se ejecuta sobre el clon SECURITY_LAKE_DEV, nunca sobre producción.
-- =====================================================================
USE WAREHOUSE SOC_WH;
ALTER SESSION SET QUERY_TAG = 'workshop_09';

-- ---------------------------------------------------------------------
-- A1) Zero-Copy Clone: entorno de desarrollo idéntico a producción en segundos
--     No copia datos (comparte micro-particiones); solo se paga lo que cambie.
--     SOC_ADMIN no tiene CREATE DATABASE: se clona con SYSADMIN y se cede la propiedad.
-- ---------------------------------------------------------------------
USE ROLE SYSADMIN;
CREATE DATABASE SECURITY_LAKE_DEV CLONE SECURITY_LAKE
  COMMENT = 'Clon de desarrollo (workshop 09) - borrar al terminar';
GRANT OWNERSHIP ON DATABASE SECURITY_LAKE_DEV TO ROLE SOC_ADMIN COPY CURRENT GRANTS;
USE ROLE SOC_ADMIN;

-- Qué se clona y en qué estado (comprobado):
--  - Dynamic tables: clonadas con datos, en SUSPENDED (motivo CLONED_AUTO_SUSPENDED).
--    Ojo: su SQL usa nombres completos (SECURITY_LAKE.BRONZE...), así que si se
--    reanudan con ALTER DYNAMIC TABLE ... RESUME leerían el BRONZE de PRODUCCIÓN.
--  - Tasks y alertas: clonadas en estado suspended (no ejecutan nada por su cuenta).
--  - Vistas con nombres completos (GOLD.DET_*) siguen apuntando a SECURITY_LAKE.
--  - Storage lifecycle policies: no se aplican a las tablas clonadas.
SHOW DYNAMIC TABLES IN DATABASE SECURITY_LAKE_DEV;   -- scheduling_state = SUSPENDED, is_clone = true
SHOW TASKS IN DATABASE SECURITY_LAKE_DEV;            -- state = suspended
SHOW ALERTS IN DATABASE SECURITY_LAKE_DEV;           -- state = suspended

-- Cambio de regla en DEV: "hay ruido, subamos el umbral del túnel DNS de 200 a 2000"
-- (regla original en 04_gold_detections.sql, DET_DNS_TUNNEL). Apuntar a DEV.SILVER.
USE SCHEMA SECURITY_LAKE_DEV.GOLD;
CREATE OR REPLACE VIEW DET_DNS_TUNNEL AS
SELECT src_ip, query_domain, event_time::DATE AS day, COUNT(*) AS queries,
       COUNT(DISTINCT query_label) AS distinct_labels, AVG(LENGTH(query_label)) AS avg_label_len, unit
FROM SECURITY_LAKE_DEV.SILVER.DNS_ACTIVITY
GROUP BY ALL
HAVING COUNT(DISTINCT query_label) > 2000 AND AVG(LENGTH(query_label)) > 30;

-- Recalcular en DEV: el procedimiento clonado escribe en las ALERTS del clon
DELETE FROM ALERTS WHERE detection = 'dns_tunnel';
CALL RUN_DETECTIONS();

-- Comparar DEV vs PROD: alertas nuevas y eliminadas por el cambio de regla
SELECT COALESCE(d.detection, p.detection) AS detection, COALESCE(d.entity, p.entity) AS entity,
       COALESCE(d.event_time, p.event_time) AS event_time,
       CASE WHEN p.alert_id IS NULL THEN 'NUEVA en DEV' ELSE 'ELIMINADA en DEV' END AS cambio
FROM SECURITY_LAKE_DEV.GOLD.ALERTS d
FULL OUTER JOIN SECURITY_LAKE.GOLD.ALERTS p
  ON d.detection = p.detection AND d.entity = p.entity AND d.event_time = p.event_time
WHERE p.alert_id IS NULL OR d.alert_id IS NULL
ORDER BY event_time;
-- Resultado: desaparecen las 2 alertas reales del túnel 10.20.5.77 (15 y 16-oct).
-- Conclusión: el cambio NO se promueve a producción. Producción no se ha tocado.

-- Resumen por detección
SELECT detection, COUNT_IF(env = 'PROD') AS prod, COUNT_IF(env = 'DEV') AS dev
FROM (SELECT 'PROD' AS env, detection FROM SECURITY_LAKE.GOLD.ALERTS
      UNION ALL SELECT 'DEV', detection FROM SECURITY_LAKE_DEV.GOLD.ALERTS)
GROUP BY 1 ORDER BY 1;

-- ---------------------------------------------------------------------
-- A2) Time Travel: "alguien ha borrado la cola de alertas"
--     SIEMPRE sobre el clon SECURITY_LAKE_DEV, no sobre producción.
-- ---------------------------------------------------------------------
USE SCHEMA SECURITY_LAKE_DEV.GOLD;
-- AT(OFFSET) no puede ir más atrás que la creación del clon (error 000707). En directo
-- ya ha pasado más de un minuto; si se ejecuta el script de golpe, esperar:
SELECT SYSTEM$WAIT(60);
SET t_antes = CURRENT_TIMESTAMP();

-- El "accidente": falta un filtro y se borran todas las alertas abiertas
DELETE FROM ALERTS WHERE status = 'NEW';
SET q_borrado = LAST_QUERY_ID();

-- ¿Cómo estaba la tabla? Tres formas de viajar en el tiempo
SELECT (SELECT COUNT(*) FROM ALERTS)                                    AS ahora,
       (SELECT COUNT(*) FROM ALERTS AT(OFFSET => -60))                  AS hace_60_segundos,
       (SELECT COUNT(*) FROM ALERTS BEFORE(STATEMENT => $q_borrado))    AS justo_antes_del_delete,
       (SELECT COUNT(*) FROM ALERTS AT(TIMESTAMP => $t_antes))          AS en_t_antes;
-- OFFSET es aproximado (puede caer antes o después de otros cambios); STATEMENT es exacto.

-- "¿Cómo era la cola a las X?" (p. ej. para el informe del incidente)
SELECT detection, entity, event_time, status
FROM ALERTS AT(TIMESTAMP => $t_antes)
ORDER BY event_time;

-- Opción 1 de recuperación: reinsertar lo borrado
INSERT INTO ALERTS
SELECT * FROM ALERTS BEFORE(STATEMENT => $q_borrado)
WHERE status = 'NEW';

-- Opción 2: clonar la tabla tal como estaba (sin tocar la actual) y comparar/sustituir
CREATE OR REPLACE TABLE ALERTS_ANTES_DEL_BORRADO CLONE ALERTS BEFORE(STATEMENT => $q_borrado);
SELECT COUNT(*) FROM ALERTS_ANTES_DEL_BORRADO;

-- DROP accidental de una tabla entera y recuperación
DROP TABLE ALERTS_ANTES_DEL_BORRADO;
UNDROP TABLE ALERTS_ANTES_DEL_BORRADO;
SELECT COUNT(*) FROM ALERTS_ANTES_DEL_BORRADO;
DROP TABLE ALERTS_ANTES_DEL_BORRADO;

-- Ventana de Time Travel por tabla (días). Por defecto 1; hasta 90 en Enterprise.
SELECT table_schema, table_name, table_type, retention_time
FROM SECURITY_LAKE.INFORMATION_SCHEMA.TABLES
WHERE table_schema <> 'INFORMATION_SCHEMA' AND table_type <> 'VIEW'
ORDER BY 1, 2;
-- Ampliar en tablas críticas (probado en el clon; en producción, decisión de coste):
ALTER TABLE SECURITY_LAKE_DEV.GOLD.ALERTS SET DATA_RETENTION_TIME_IN_DAYS = 30;
-- ALTER TABLE SECURITY_LAKE.GOLD.ALERTS SET DATA_RETENTION_TIME_IN_DAYS = 30;
-- Tras Time Travel, las tablas permanentes tienen 7 días de Fail-safe: no es
-- consultable por el cliente, solo recuperable por Soporte de Snowflake (último recurso).
-- Las tablas TRANSIENT/TEMPORARY no tienen Fail-safe.

-- Evidencia forense: congelar el lake tal como estaba en un instante concreto
-- (limitado a la ventana de Time Travel de cada tabla; probado con un clon de prueba).
-- USE ROLE SYSADMIN;
-- CREATE DATABASE SECURITY_LAKE_EVIDENCIA_20261017
--   CLONE SECURITY_LAKE AT(TIMESTAMP => '2026-10-17 09:00:00 +02:00'::TIMESTAMP_TZ)
--   COMMENT = 'Evidencia incidente exfiltración 10.20.8.15 - solo lectura';
-- GRANT OWNERSHIP ON DATABASE SECURITY_LAKE_EVIDENCIA_20261017 TO ROLE SOC_ADMIN COPY CURRENT GRANTS;
-- GRANT USAGE ON DATABASE SECURITY_LAKE_EVIDENCIA_20261017 TO ROLE THREAT_HUNTER;
-- Quién lo creó y cuándo queda en ACCOUNT_USAGE.QUERY_HISTORY / ACCESS_HISTORY (10.4).

-- ---------------------------------------------------------------------
-- Al terminar: eliminar el clon (también incluido en 99_teardown.sql)
-- ---------------------------------------------------------------------
-- USE ROLE SOC_ADMIN;
-- DROP DATABASE IF EXISTS SECURITY_LAKE_DEV;
ALTER SESSION UNSET QUERY_TAG;
