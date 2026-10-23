USE ROLE SOC_ADMIN;
USE SCHEMA SECURITY_LAKE.BRONZE;
-- Que se ha cargado, cuando y con que errores (idempotente: re-ejecutar el COPY no duplica)
SELECT file_name, row_count, error_count, status, last_load_time
FROM TABLE(INFORMATION_SCHEMA.COPY_HISTORY(TABLE_NAME=>'DNS_RAW_DEMO', START_TIME=>DATEADD(hour,-1,CURRENT_TIMESTAMP())))
ORDER BY file_name;
