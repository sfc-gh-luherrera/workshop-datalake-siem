-- =====================================================================
-- 06 · Fraude SIM swap / portabilidad: clasificación y cola de investigación
-- Histórico etiquetado (is_fraud) hasta el 17-oct; se puntúan 18–21 oct.
-- Sembrado: anillo en tienda S-0457 / agente A-1123 del 18 al 20-oct.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- El modelo se construye en directo con Cortex Code: prompts/ml_fraude_sim.md
-- Respaldo (ejecutado en la preparación): sql/backup/ml_modelos_respaldo.sql
--   crea SIM_TRAIN, SIM_FRAUD_MODEL y SIM_SCORED (usada por 08, Streamlit y las guías)
--   y reaplica la etiqueta PII y MASK_PII_HASH sobre SIM_SCORED.msisdn.

-- Calidad del modelo e importancia de variables
CALL SIM_FRAUD_MODEL!SHOW_EVALUATION_METRICS();
CALL SIM_FRAUD_MODEL!SHOW_FEATURE_IMPORTANCE();

-- Cola de investigación de la mañana: solicitudes de mayor riesgo
SELECT request_ts, msisdn, request_type, store_id, agent_id, ROUND(fraud_score, 3) AS score
FROM SIM_SCORED WHERE fraud_score > 0.5 ORDER BY fraud_score DESC LIMIT 25;

-- Fraude interno: agentes/tiendas con concentración anómala de solicitudes de alto riesgo
SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
