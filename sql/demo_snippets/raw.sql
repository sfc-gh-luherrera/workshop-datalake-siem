USE ROLE SOC_ADMIN;
USE SCHEMA SECURITY_LAKE.BRONZE;
-- Consultar directamente el fichero en S3, sin cargarlo: dominios sospechosamente largos
SELECT METADATA$FILENAME AS fichero,
       $1:ts::timestamp AS ts, $1:client_ip::string AS client_ip,
       $1:query::string AS query, LENGTH($1:query::string) AS len
FROM @S3_LOGS/dns/2026/10/15/ (FILE_FORMAT => 'FF_JSON')
WHERE LENGTH($1:query::string) > 40
LIMIT 20;
