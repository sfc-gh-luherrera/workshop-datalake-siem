-- =====================================================================
-- backup · Modelos ML de respaldo (ejecutar en la PREPARACIÓN del entorno)
-- En el workshop los modelos se construyen con Cortex Code siguiendo
-- prompts/ml_anomalias_salida.md y prompts/ml_fraude_sim.md. Este script deja
-- creados los mismos objetos para que los bloques siguientes (07 triage,
-- 08 gobierno, demo_snippets, Streamlit) tengan datos aunque falle la demo.
-- Objetos: GOLD.NET_DAILY_SUBNET, EGRESS_DAILY_SUBNET, NET_ANOMALY_MODEL, EGRESS_ANOMALIES,
--          NET_ANOMALIES (compatibilidad), SIM_TRAIN, SIM_FRAUD_MODEL, SIM_SCORED
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- ---------------------------------------------------------------------
-- 1) Anomalías en tráfico saliente diario por subred /24
--    Entrenamiento: hasta el 16-oct (día anterior a la exfiltración sembrada).
--    Detección: 17–21 oct. Esperado: 10.20.8 el 17-oct ~1000x sobre lo previsto.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW NET_DAILY_SUBNET AS
SELECT REGEXP_SUBSTR(src_ip, '^[0-9]+[.][0-9]+[.][0-9]+') AS subnet,
       event_time::DATE::TIMESTAMP_NTZ AS day, SUM(bytes_out)::FLOAT AS bytes_out
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
WHERE source = 'netflow'
GROUP BY ALL;

-- IMPORTANTE: materializar la serie en una tabla. NETWORK_ACTIVITY tiene la row access
-- policy RAP_BY_UNIT (08) y, dentro del entrenamiento ML, IS_ROLE_IN_SESSION no ve los
-- roles de la sesión: entrenar sobre la vista falla con "input_data is empty".
CREATE OR REPLACE TABLE EGRESS_DAILY_SUBNET COPY GRANTS AS SELECT * FROM NET_DAILY_SUBNET;

CREATE OR REPLACE SNOWFLAKE.ML.ANOMALY_DETECTION NET_ANOMALY_MODEL(
  INPUT_DATA => TABLE(SELECT * FROM EGRESS_DAILY_SUBNET WHERE day < '2026-10-17'),
  SERIES_COLNAME => 'SUBNET', TIMESTAMP_COLNAME => 'DAY', TARGET_COLNAME => 'BYTES_OUT',
  LABEL_COLNAME => '');

CREATE OR REPLACE TABLE EGRESS_ANOMALIES COPY GRANTS AS
SELECT * FROM TABLE(NET_ANOMALY_MODEL!DETECT_ANOMALIES(
  INPUT_DATA => TABLE(SELECT * FROM EGRESS_DAILY_SUBNET WHERE day >= '2026-10-17'),
  SERIES_COLNAME => 'SUBNET', TIMESTAMP_COLNAME => 'DAY', TARGET_COLNAME => 'BYTES_OUT',
  CONFIG_OBJECT => {'prediction_interval': 0.999}));

-- Compatibilidad: demo_snippets/ml.sql y las guías consultan NET_ANOMALIES
CREATE OR REPLACE TABLE NET_ANOMALIES COPY GRANTS AS SELECT * FROM EGRESS_ANOMALIES;

-- Comprobación: debe salir 10.20.8 / 2026-10-17 en primer lugar
SELECT series, ts, ROUND(y/1e6, 1) AS mb_out, ROUND(forecast/1e6, 1) AS mb_expected,
       ROUND(upper_bound/1e6, 1) AS mb_upper, ROUND(y / forecast, 1) AS x_over_forecast
FROM EGRESS_ANOMALIES WHERE is_anomaly ORDER BY x_over_forecast DESC;

-- ---------------------------------------------------------------------
-- 2) Fraude SIM swap / portabilidad (clasificación). Ver 06_sim_swap_ml.sql
--    Esperado: anillo S-0457 / A-1123 con 75 solicitudes de riesgo.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW SIM_TRAIN AS
SELECT request_type, channel, new_device, new_location, requests_24h, account_age_days,
       HOUR(request_ts) AS hour_of_day, is_fraud::BOOLEAN AS is_fraud
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS
WHERE is_fraud IS NOT NULL;

CREATE OR REPLACE SNOWFLAKE.ML.CLASSIFICATION SIM_FRAUD_MODEL(
  INPUT_DATA => SYSTEM$REFERENCE('VIEW', 'SIM_TRAIN'),
  TARGET_COLNAME => 'IS_FRAUD');

CREATE OR REPLACE TABLE SIM_SCORED COPY GRANTS AS
SELECT s.request_ts, s.msisdn, s.request_type, s.channel, s.store_id, s.agent_id, s.unit,
       SIM_FRAUD_MODEL!PREDICT(INPUT_DATA => OBJECT_CONSTRUCT(
         'REQUEST_TYPE', s.request_type, 'CHANNEL', s.channel, 'NEW_DEVICE', s.new_device,
         'NEW_LOCATION', s.new_location, 'REQUESTS_24H', s.requests_24h,
         'ACCOUNT_AGE_DAYS', s.account_age_days, 'HOUR_OF_DAY', HOUR(s.request_ts))):probability:"True"::FLOAT AS fraud_score
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS s
WHERE s.is_fraud IS NULL;

-- SIM_SCORED es nueva: reaplicar etiqueta y enmascaramiento de 08.
-- En el primer montaje 08 aún no existe: el bloque lo omite y 08 los aplica después.
EXECUTE IMMEDIATE $$
BEGIN
  ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET TAG SECURITY_LAKE.GOVERNANCE.DATA_SENSITIVITY = 'PII';
  ALTER TABLE SECURITY_LAKE.GOLD.SIM_SCORED MODIFY COLUMN msisdn SET MASKING POLICY SECURITY_LAKE.GOVERNANCE.MASK_PII_HASH FORCE;
  RETURN 'PII reaplicado en SIM_SCORED';
EXCEPTION WHEN OTHER THEN
  RETURN 'Omitido (ejecutar 08 después): ' || SQLERRM;
END;
$$;

SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
