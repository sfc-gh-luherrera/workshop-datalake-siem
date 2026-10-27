# ML con Cortex Code: fraude en solicitudes de SIM (SIM swap / portabilidad)

Objetivo: entrenar un clasificador con `SNOWFLAKE.ML.CLASSIFICATION` sobre el histórico
etiquetado y sacar a la luz el anillo sembrado en la tienda **S-0457** / agente **A-1123**
(18–20 oct). Basado en `sql/06_sim_swap_ml.sql`.

- Rol: `SOC_ADMIN` · Warehouse: `SOC_WH` · Esquema: `SECURITY_LAKE.GOLD`
- Respaldo: `sql/backup/ml_modelos_respaldo.sql` (mismos nombres de objetos).

---

## 1. Descubrimiento de los datos

**Prompt**

```
Describe la tabla SECURITY_LAKE.BRONZE.SIM_REQUESTS: columnas, número de filas,
cuántas tienen etiqueta is_fraud y cuántas no, y el porcentaje de fraude en las etiquetadas.
¿Qué rango de fechas tienen las filas sin etiquetar?
```

**Resultado esperado**: 58 650 filas etiquetadas (1 187 fraudes, ~2 %) y 675 sin etiquetar,
que son las solicitudes nuevas del 18 al 21-oct que hay que puntuar.

**Checkpoint**

```sql
SELECT COUNT_IF(is_fraud IS NOT NULL) AS etiquetadas, COUNT_IF(is_fraud = 1) AS fraudes,
       COUNT_IF(is_fraud IS NULL) AS sin_etiqueta,
       MIN(IFF(is_fraud IS NULL, request_ts, NULL)) AS desde_nuevas,
       MAX(IFF(is_fraud IS NULL, request_ts, NULL)) AS hasta_nuevas
FROM SECURITY_LAKE.BRONZE.SIM_REQUESTS;
```

---

## 2. Vista de entrenamiento

**Prompt**

```
Crea la vista SECURITY_LAKE.GOLD.SIM_TRAIN con las filas etiquetadas de SIM_REQUESTS y estas
variables: request_type, channel, new_device, new_location, requests_24h, account_age_days,
la hora de la solicitud como hour_of_day y is_fraud convertido a BOOLEAN.
No incluyas msisdn, tienda ni agente: no deben ser variables del modelo.
```

**Resultado esperado**: vista creada; 58 650 filas, 1 187 con `is_fraud = TRUE` (2,02 %).

**Checkpoint**

```sql
SELECT COUNT(*) AS filas, COUNT_IF(is_fraud) AS fraudes, ROUND(AVG(is_fraud::INT) * 100, 2) AS pct_fraude
FROM SECURITY_LAKE.GOLD.SIM_TRAIN;
-- 58650 | 1187 | 2.02
```

---

## 3. Entrenar y evaluar el clasificador

**Prompt**

```
Entrena SNOWFLAKE.ML.CLASSIFICATION llamado SECURITY_LAKE.GOLD.SIM_FRAUD_MODEL sobre la vista
SIM_TRAIN (usa SYSTEM$REFERENCE('VIEW', ...)) con objetivo IS_FRAUD. Muéstrame las métricas
de evaluación y la importancia de variables, y explica cuáles pesan más y por qué tiene
sentido para un fraude de SIM swap.
```

**Resultado esperado**: modelo creado (~15 s en XS). En este dataset sintético las métricas de
evaluación salen perfectas (precision/recall 1 en ambas clases): comentar que con datos reales
no será así. Variables más importantes: `ACCOUNT_AGE_DAYS`, `REQUESTS_24H`, `REQUEST_TYPE`,
`HOUR_OF_DAY`.

**Checkpoint**

```sql
CALL SECURITY_LAKE.GOLD.SIM_FRAUD_MODEL!SHOW_EVALUATION_METRICS();
CALL SECURITY_LAKE.GOLD.SIM_FRAUD_MODEL!SHOW_FEATURE_IMPORTANCE();
-- rank 1: ACCOUNT_AGE_DAYS, rank 2: REQUESTS_24H
```

---

## 4. Puntuar las solicitudes nuevas

**Prompt**

```
Puntúa con SIM_FRAUD_MODEL!PREDICT las solicitudes sin etiqueta de SIM_REQUESTS y guarda en
SECURITY_LAKE.GOLD.SIM_SCORED: request_ts, msisdn, request_type, channel, store_id, agent_id,
unit y fraud_score (la probabilidad de la clase "True" como FLOAT). Mantén los permisos
existentes de la tabla (COPY GRANTS).
```

**Resultado esperado**: 675 filas puntuadas.

> `SIM_SCORED` es una tabla nueva: pierde la etiqueta PII y la máscara de `msisdn`.
> Reaplicarlas pidiendo a Cortex Code que ejecute el bloque correspondiente de
> `sql/08_governance.sql` (o el bloque final del script de respaldo).

**Checkpoint**

```sql
SELECT COUNT(*) AS puntuadas, COUNT_IF(fraud_score > 0.5) AS alto_riesgo FROM SECURITY_LAKE.GOLD.SIM_SCORED;
SELECT policy_name FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_NAME => 'SECURITY_LAKE.GOLD.SIM_SCORED', REF_ENTITY_DOMAIN => 'TABLE'));
-- 675 | 86 ; MASK_PII_HASH
```

---

## 5. Cola de investigación y fraude interno

**Prompt**

```
Con SIM_SCORED, dame la cola de investigación de esta mañana (las 25 solicitudes con mayor
fraud_score > 0.5) y después agrupa por tienda y agente para ver si hay concentración anómala
de solicitudes de alto riesgo (5 o más). ¿Qué indica el resultado y qué harías a continuación?
```

**Resultado esperado**: un único grupo destaca, **S-0457 / A-1123 con 75 solicitudes de alto
riesgo** y score medio 1,0: patrón de fraude interno (un agente que procesa cambios de SIM para
un anillo). Siguiente paso: bloquear al agente, revisar las líneas afectadas, avisar a fraude.

**Checkpoint**

```sql
SELECT store_id, agent_id, COUNT(*) AS high_risk, ROUND(AVG(fraud_score), 2) AS avg_score
FROM SECURITY_LAKE.GOLD.SIM_SCORED WHERE fraud_score > 0.5
GROUP BY ALL HAVING COUNT(*) >= 5 ORDER BY high_risk DESC;
-- S-0457 | A-1123 | 75 | 1
```
