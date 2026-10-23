-- =====================================================================
-- 01b · ALTERNATIVA SIN AWS: stage interno con el mismo nombre (S3_LOGS)
-- Úsalo para ensayar el workshop sin bucket. Los scripts 02-08 no cambian.
-- Subir ficheros: python generator/upload_internal.py --dir ./out
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.BRONZE;

CREATE STAGE IF NOT EXISTS S3_LOGS DIRECTORY = (ENABLE = TRUE)
  COMMENT = 'Ensayo: stage interno que simula s3://workshop-datalake-siem';

CREATE FILE FORMAT IF NOT EXISTS FF_JSON TYPE = JSON STRIP_OUTER_ARRAY = FALSE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_LINES TYPE = CSV FIELD_DELIMITER = NONE RECORD_DELIMITER = '\n'
  ESCAPE_UNENCLOSED_FIELD = NONE COMPRESSION = AUTO;
CREATE FILE FORMAT IF NOT EXISTS FF_CSV TYPE = CSV SKIP_HEADER = 1 FIELD_OPTIONALLY_ENCLOSED_BY = '"'
  EMPTY_FIELD_AS_NULL = TRUE COMPRESSION = AUTO;
