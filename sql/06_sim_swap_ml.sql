-- =====================================================================
-- 06 · Fraude SIM swap / portabilidad: clasificación y cola de investigación
-- Histórico etiquetado (is_fraud) hasta el 17-oct; se puntúan 18–21 oct.
-- Sembrado: anillo en tienda S-0457 / agente A-1123 del 18 al 20-oct.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

CREATE OR REPLACE VIEW SIM_TRAIN AS
SELECT request_type, channel, new_device, new_location, requests_24h, account_age_days,
       HOUR(request_ts) AS hour_of_day, is_fraud::BOOLEAN AS is_fraud
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS
WHERE is_fraud IS NOT NULL;

CREATE OR REPLACE SNOWFLAKE.ML.CLASSIFICATION SIM_FRAUD_MODEL(
  INPUT_DATA => SYSTEM$REFERENCE('VIEW', 'SIM_TRAIN'),
  TARGET_COLNAME => 'IS_FRAUD');

-- Calidad del modelo e importancia de variables
CALL SIM_FRAUD_MODEL!SHOW_EVALUATION_METRICS();
CALL SIM_FRAUD_MODEL!SHOW_FEATURE_IMPORTANCE();

-- Puntuación diaria de las solicitudes nuevas
CREATE OR REPLACE TABLE SIM_SCORED AS
SELECT s.request_ts, s.msisdn, s.request_type, s.channel, s.store_id, s.agent_id, s.unit,
       SIM_FRAUD_MODEL!PREDICT(INPUT_DATA => OBJECT_CONSTRUCT(
         'REQUEST_TYPE', s.request_type, 'CHANNEL', s.channel, 'NEW_DEVICE', s.new_device,
         'NEW_LOCATION', s.new_location, 'REQUESTS_24H', s.requests_24h,
         'ACCOUNT_AGE_DAYS', s.account_age_days, 'HOUR_OF_DAY', HOUR(s.request_ts))):probability:"True"::FLOAT AS fraud_score
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS s
WHERE s.is_fraud IS NULL;

-- Cola de investigación de la mañana: solicitudes de mayor riesgo
SELECT request_ts, msisdn, request_type, store_id, agent_id, ROUND(fraud_score, 3) AS score
FROM SIM_SCORED WHERE fraud_score > 0.5 ORDER BY fraud_score DESC LIMIT 25;

-- Fraude interno: agentes/tiendas con concentración anómala de solicitudes de alto riesgo
SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
