-- =====================================================================
-- 01 · Conexión a S3: storage integration, stage externo y formatos
-- Ejecutar con ACCOUNTADMIN. Sustituir <AWS_ACCOUNT_ID> y el nombre del rol IAM.
-- =====================================================================
USE ROLE ACCOUNTADMIN;

CREATE STORAGE INTEGRATION IF NOT EXISTS S3_SIEM_INT
  TYPE = EXTERNAL_STAGE
  STORAGE_PROVIDER = 'S3'
  ENABLED = TRUE
  STORAGE_AWS_ROLE_ARN = 'arn:aws:iam::<AWS_ACCOUNT_ID>:role/snowflake-workshop-datalake-siem'
  STORAGE_ALLOWED_LOCATIONS = ('s3://workshop-datalake-siem/');

-- Copiar STORAGE_AWS_IAM_USER_ARN y STORAGE_AWS_EXTERNAL_ID a la trust policy del rol IAM
DESC INTEGRATION S3_SIEM_INT;

GRANT USAGE ON INTEGRATION S3_SIEM_INT TO ROLE SOC_ADMIN;

USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.BRONZE;

CREATE STAGE IF NOT EXISTS S3_LOGS
  URL = 's3://workshop-datalake-siem/'
  STORAGE_INTEGRATION = S3_SIEM_INT
  DIRECTORY = (ENABLE = TRUE)
  COMMENT = 'Logs de seguridad en S3';

-- Formatos: JSON por líneas, texto syslog (una línea = un evento), CSV con cabecera
CREATE FILE FORMAT IF NOT EXISTS FF_JSON TYPE = JSON STRIP_OUTER_ARRAY = FALSE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_LINES TYPE = CSV FIELD_DELIMITER = NONE RECORD_DELIMITER = '\n'
  ESCAPE_UNENCLOSED_FIELD = NONE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_CSV TYPE = CSV SKIP_HEADER = 1 FIELD_OPTIONALLY_ENCLOSED_BY = '"'
  EMPTY_FIELD_AS_NULL = TRUE COMPRESSION = AUTO;

-- Demo en directo: ver lo que hay y consultar en sitio antes de cargar
LIST @S3_LOGS/dns/2026/10/;
SELECT $1 FROM @S3_LOGS/dns/2026/10/15/ (FILE_FORMAT => 'FF_JSON') LIMIT 10;
