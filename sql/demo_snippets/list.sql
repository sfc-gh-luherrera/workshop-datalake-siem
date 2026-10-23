USE ROLE SOC_ADMIN;
USE SCHEMA SECURITY_LAKE.BRONZE;
-- Ficheros de un mes de DNS directamente en S3
LIST @S3_LOGS/dns/2026/10/;
