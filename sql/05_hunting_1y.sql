-- =====================================================================
-- 05 · Hunting sobre 1 año: raw vs normalizado, aceleración, exportación, coste
-- =====================================================================
USE ROLE THREAT_HUNTER;
USE WAREHOUSE SOC_WH;
ALTER SESSION SET USE_CACHED_RESULT = FALSE;   -- medir sin caché de resultados
ALTER SESSION SET QUERY_TAG = 'workshop_hunting';

-- 1) Búsqueda en el evento ORIGINAL sin normalizar (4.3): texto libre sobre el VARIANT
--    "¿Alguien resolvió alguna vez este dominio en el último año?"
SELECT raw:ts::TIMESTAMP_NTZ AS ts, raw:client_ip::STRING AS host, raw:query::STRING AS query, src_file
FROM SECURITY_LAKE.BRONZE.DNS_RAW
WHERE SEARCH(raw, 'update-check-srv.com')
ORDER BY ts;

--    Mismo patrón en syslog crudo de firewall (texto)
SELECT raw_line FROM SECURITY_LAKE.BRONZE.FW_RAW
WHERE raw_line ILIKE '%action=deny%' AND raw_line ILIKE '%dport=22%' LIMIT 20;

-- 2) Hunting sobre el modelo común (4.4): todo lo que tocó un host en 12 meses
SELECT class, COUNT(*) AS events, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.SILVER.ALL_EVENTS
WHERE (src_ip = '10.20.8.15' OR dst_ip = '10.20.8.15')
  AND event_time >= DATEADD('month', -12, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY class;

-- 3) Consulta cronometrada (4.1): top destinos externos por volumen en 1 año.
--    Anotar el tiempo (Query History) en XS y repetir en L para mostrar elasticidad.
SELECT dst_ip, COUNT(DISTINCT src_ip) AS hosts, SUM(bytes_out) AS bytes_out
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
WHERE source = 'netflow' AND event_time >= DATEADD('year', -1, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY dst_ip ORDER BY bytes_out DESC LIMIT 20;

USE ROLE SOC_ADMIN;
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'LARGE';
-- (repetir la consulta 3)
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'XSMALL';

-- 4) Aceleración (4.8): Search Optimization para búsquedas puntuales sobre el raw
--    Ejecutar la búsqueda 1 antes y después; comparar "partitions scanned" en el Query Profile.
ALTER TABLE SECURITY_LAKE.BRONZE.DNS_RAW ADD SEARCH OPTIMIZATION ON FULL_TEXT(raw), EQUALITY(raw:client_ip);
-- Progreso de la construcción (search_optimization_progress = 100 cuando termina)
SHOW TABLES LIKE 'DNS_RAW' IN SCHEMA SECURITY_LAKE.BRONZE;

-- 5) Exportación (4.5): resultados a un stage (CSV) para compartir con CSIRT/forense
COPY INTO @SECURITY_LAKE.BRONZE.S3_LOGS/exports/ioc_hits_
  FROM (SELECT * FROM SECURITY_LAKE.GOLD.DET_IOC_HITS)
  FILE_FORMAT = (TYPE = CSV COMPRESSION = GZIP) HEADER = TRUE OVERWRITE = TRUE;
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/exports/;

-- 6) Coste de lo que acabamos de hacer (9.8)
SELECT LEFT(query_text, 60) AS query, warehouse_size,
       total_elapsed_time / 1000 AS seconds, bytes_scanned, rows_produced
FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.QUERY_HISTORY_BY_SESSION())
WHERE query_tag = 'workshop_hunting' AND execution_status = 'SUCCESS' AND query_type = 'SELECT'
ORDER BY start_time DESC LIMIT 20;
-- Particiones escaneadas/totales: ver Query Profile en Snowsight (antes/después de Search Optimization)
-- Créditos por warehouse (latencia de ACCOUNT_USAGE ~1-3 h):
SELECT warehouse_name, SUM(credits_used) AS credits
FROM SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY
WHERE warehouse_name = 'SOC_WH' AND start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY 1;
