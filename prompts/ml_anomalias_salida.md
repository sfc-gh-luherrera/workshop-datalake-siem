# ML con Cortex Code: anomalías en el tráfico saliente

Objetivo: detectar la exfiltración sembrada (subred **10.20.8**, **17-oct-2026**) con
`SNOWFLAKE.ML.ANOMALY_DETECTION`, sin escribir SQL a mano. Cada paso es un prompt para
copiar y pegar en Cortex Code, el resultado esperado y una SQL de comprobación.

- Rol: `SOC_ADMIN` · Warehouse: `SOC_WH` · Esquema de salida: `SECURITY_LAKE.GOLD`
- Respaldo si algo falla: `sql/backup/ml_modelos_respaldo.sql` (crea los mismos objetos con los mismos nombres).

---

## 1. Descubrimiento de la tabla de red

**Prompt**

```
Busca en SECURITY_LAKE.SILVER la tabla con la actividad de red (NetFlow y firewall).
Dime qué columnas tiene, qué fuentes contiene (columna source), el rango de fechas
y qué fuente trae el volumen de bytes salientes. No crees nada todavía.
```

**Resultado esperado**: identifica `SILVER.NETWORK_ACTIVITY` (dynamic table). Dos fuentes:
`netflow` (~790 000 filas, todas con `bytes_out`) y `fw` (~474 000 filas, `bytes_out` vacío).
Datos del 22-sep-2025 al 21-oct-2026. Solo `netflow` sirve para medir volumen.

**Checkpoint**

```sql
SELECT source, COUNT(*) AS filas, COUNT(bytes_out) AS con_bytes,
       MIN(event_time) AS desde, MAX(event_time) AS hasta
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY source ORDER BY source;
```

---

## 2. Serie temporal diaria de bytes salientes por subred

**Prompt**

```
Crea en SECURITY_LAKE.GOLD la vista NET_DAILY_SUBNET con el total diario de bytes_out
por subred /24 (los tres primeros octetos de src_ip, columna SUBNET), solo source = 'netflow'.
Columnas: SUBNET (string), DAY (TIMESTAMP_NTZ, truncado al día), BYTES_OUT (FLOAT).
Después materializa la vista en la tabla GOLD.EGRESS_DAILY_SUBNET (CREATE OR REPLACE TABLE AS),
porque NETWORK_ACTIVITY tiene una row access policy y el entrenamiento ML no debe leerla
directamente. Enséñame cuántas subredes y días hay, y el valor de la subred 10.20.8
el 17-oct-2026 frente a su mediana.
```

**Resultado esperado**: 9 subredes (10.20.1 a 10.20.9), 395 días cada una, 3 555 puntos.
La mediana diaria ronda 5 MB; 10.20.8 el 17-oct tiene ~5 374 MB (unas 1 000 veces más).
El entrenamiento usará los días **anteriores al 17-oct** (3 510 puntos).

**Checkpoint**

```sql
SELECT COUNT(DISTINCT subnet) AS subredes, COUNT(*) AS puntos, MIN(day) AS desde, MAX(day) AS hasta,
       COUNT_IF(day < '2026-10-17') AS puntos_entreno,
       MAX(IFF(subnet = '10.20.8' AND day = '2026-10-17', ROUND(bytes_out/1e6), NULL)) AS mb_10_20_8_17oct
FROM SECURITY_LAKE.GOLD.EGRESS_DAILY_SUBNET;
-- 9 | 3555 | 2025-09-22 | 2026-10-21 | 3510 | 5374
```

> Si el agente entrena directamente sobre la vista, el error es
> `input_data is empty`: la row access policy `RAP_BY_UNIT` filtra todo dentro del
> entrenamiento. Por eso se materializa la tabla.

---

## 3. Entrenar el modelo de anomalías

**Prompt**

```
Entrena un modelo SNOWFLAKE.ML.ANOMALY_DETECTION llamado SECURITY_LAKE.GOLD.NET_ANOMALY_MODEL
sobre GOLD.EGRESS_DAILY_SUBNET, una serie por SUBNET, timestamp DAY, objetivo BYTES_OUT,
sin etiquetas (LABEL_COLNAME => ''), usando solo los días anteriores al 2026-10-17.
Explícame en dos frases qué aprende el modelo.
```

**Resultado esperado**: `Instance NET_ANOMALY_MODEL successfully created`.
El modelo aprende el comportamiento normal de cada subred por separado (es un modelo
de previsión por serie) y no necesita ejemplos de ataques.

**Checkpoint**

```sql
SHOW SNOWFLAKE.ML.ANOMALY_DETECTION IN SCHEMA SECURITY_LAKE.GOLD;
-- 1 fila: NET_ANOMALY_MODEL, owner SOC_ADMIN
```

---

## 4. Detectar y guardar resultados

**Prompt**

```
Usa NET_ANOMALY_MODEL!DETECT_ANOMALIES sobre GOLD.EGRESS_DAILY_SUBNET para los días
desde el 2026-10-17 (mismas columnas que en el entrenamiento) con
CONFIG_OBJECT => {'prediction_interval': 0.999} y guarda el resultado en la tabla
SECURITY_LAKE.GOLD.EGRESS_ANOMALIES. Lista las anomalías ordenadas por cuántas veces
supera el valor observado al previsto.
```

**Resultado esperado**: 45 filas (9 subredes x 5 días), 2 anomalías. La primera es
**10.20.8 el 17-oct: 5 374 MB frente a 5,3 MB previstos (~1 005x)**. La segunda
(10.20.9 el 19-oct, 8,9 MB frente a un máximo de 8,2 MB) es un falso positivo menor:
buen momento para hablar de umbrales.

**Checkpoint**

```sql
SELECT COUNT(*) AS filas, COUNT_IF(is_anomaly) AS anomalias,
       MAX_BY(series || ' ' || ts::DATE, distance) AS top_anomalia,
       ROUND(MAX(y / forecast)) AS max_x_sobre_previsto
FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES;
-- 45 | 2 | 10.20.8 2026-10-17 | 1005
```

---

## 5. Explicar y visualizar observado frente a rango esperado

**Prompt**

```
Explica para un analista SOC qué significan las columnas Y, FORECAST, LOWER_BOUND,
UPPER_BOUND, IS_ANOMALY y DISTANCE de GOLD.EGRESS_ANOMALIES. Después dibuja un gráfico
de líneas en MB por día para las subredes 10.20.8 y 10.20.1 con el valor observado,
el previsto y la banda mínimo–máximo. Termina con la siguiente acción recomendada
(qué host de 10.20.8 investigar y con qué detección o runbook).
```

**Resultado esperado**: en 10.20.1 el valor observado queda siempre dentro de la banda
(~1–9 MB). En 10.20.8 el 17-oct se sale de la escala (5 374 MB frente a un máximo de 9 MB) y
vuelve a la normalidad al día siguiente. Siguiente paso: el host `10.20.8.15` (alerta
`exfiltration` en `GOLD.ALERTS`, IOC `45.137.21.9`) y el runbook `rb_exfiltration.md`.

**Checkpoint**

```sql
SELECT series, ts::DATE AS dia, ROUND(y/1e6, 1) AS mb_observado, ROUND(forecast/1e6, 1) AS mb_previsto,
       ROUND(lower_bound/1e6, 1) AS mb_min, ROUND(upper_bound/1e6, 1) AS mb_max, is_anomaly
FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES
WHERE series IN ('10.20.8', '10.20.1') ORDER BY series, dia;
-- 10 filas; solo 10.20.8 / 2026-10-17 con is_anomaly = TRUE
```

---

Compatibilidad: `demo_snippets/ml.sql` y las guías leen `GOLD.NET_ANOMALIES`. Si se ha
seguido este flujo en lugar del respaldo, refrescarla:
`CREATE OR REPLACE TABLE SECURITY_LAKE.GOLD.NET_ANOMALIES COPY GRANTS AS SELECT * FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES;`
