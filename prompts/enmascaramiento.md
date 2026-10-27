# Gobierno con Cortex Code: vista + enmascaramiento de un dato personal

Objetivo: publicar una vista para el analista sobre las solicitudes SIM de alto riesgo y
ocultar el identificador del agente comercial (dato personal de empleado) con una masking
policy, comprobando el resultado por rol. Basado en `sql/08_governance.sql`
(`MASK_PII_HASH`, `RAP_BY_UNIT`, separación SOC_ANALYST / THREAT_HUNTER).

- Rol: `SOC_ADMIN` · Warehouse: `SOC_WH`
- Requisitos: `08_governance.sql` ejecutado y `GOLD.SIM_SCORED` existente (06 o respaldo).

---

## 1. Ver qué está ya protegido

**Prompt**

```
¿Qué masking policies y etiquetas hay en SECURITY_LAKE.GOVERNANCE y a qué columnas están
aplicadas? Dime en concreto qué columnas de GOLD.SIM_SCORED están protegidas y cuáles no.
```

**Resultado esperado**: `MASK_PII_HASH` (hash determinista salvo para `THREAT_HUNTER`)
aplicada a `SILVER.AUTH_ACTIVITY.user_name`, `BRONZE.SIM_REQUESTS.msisdn` y
`GOLD.SIM_SCORED.msisdn`; etiqueta `DATA_SENSITIVITY = 'PII'` en esas columnas.
`agent_id` de `SIM_SCORED` **no** está protegido.

**Checkpoint**

```sql
SELECT ref_column_name, policy_name, policy_kind FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_NAME => 'SECURITY_LAKE.GOLD.SIM_SCORED', REF_ENTITY_DOMAIN => 'TABLE'));
-- MSISDN | MASK_PII_HASH | MASKING_POLICY
```

---

## 2. Crear la vista para el analista

**Prompt**

```
Crea la vista SECURITY_LAKE.GOLD.V_SIM_RIESGO_AGENTES con request_ts, store_id, agent_id,
msisdn, request_type y fraud_score redondeado a 3 decimales, solo para fraud_score > 0.5,
y concede SELECT sobre ella al rol SOC_ANALYST (las future grants de GOLD no cubren vistas).
```

**Resultado esperado**: vista creada con 86 filas; grant aplicado.

**Checkpoint**

```sql
SELECT COUNT(*) FROM SECURITY_LAKE.GOLD.V_SIM_RIESGO_AGENTES;   -- 86
SHOW GRANTS ON VIEW SECURITY_LAKE.GOLD.V_SIM_RIESGO_AGENTES;     -- SELECT a SOC_ANALYST
```

---

## 3. Masking policy sobre el identificador del agente

**Prompt**

```
Crea en SECURITY_LAKE.GOVERNANCE la masking policy MASK_AGENT_ID para STRING que deje el valor
en claro si el rol THREAT_HUNTER está en la sesión (IS_ROLE_IN_SESSION) y, si no, sustituya
los dígitos por asteriscos (A-1123 -> A-****), para que el analista pueda agrupar por tienda
pero no identificar al empleado. Aplícala a la columna agent_id de la vista
GOLD.V_SIM_RIESGO_AGENTES y etiqueta la columna con DATA_SENSITIVITY = 'PII'.
```

**Resultado esperado**: policy creada y aplicada a la vista. El `msisdn` de la vista ya sale
enmascarado sin hacer nada: la policy de la tabla base (`SIM_SCORED`) se aplica también a
través de la vista.

**Checkpoint**

```sql
SELECT ref_column_name, policy_name FROM TABLE(SECURITY_LAKE.INFORMATION_SCHEMA.POLICY_REFERENCES(
  REF_ENTITY_NAME => 'SECURITY_LAKE.GOLD.V_SIM_RIESGO_AGENTES', REF_ENTITY_DOMAIN => 'VIEW'));
-- AGENT_ID | MASK_AGENT_ID   (la de msisdn está en la tabla base, no en la vista)
```

---

## 4. Verificar por rol

**Prompt**

```
Comprueba la vista con dos roles. Primero USE ROLE SOC_ANALYST; USE SECONDARY ROLES NONE;
USE WAREHOUSE SOC_WH; y consulta store_id, agent_id y msisdn (2 filas). Después
USE ROLE THREAT_HUNTER y repite. Compara y explica la diferencia. Al terminar vuelve a
USE ROLE SOC_ADMIN; USE SECONDARY ROLES ALL;
```

**Resultado esperado**

| Rol | store_id | agent_id | msisdn |
|---|---|---|---|
| SOC_ANALYST | S-0457 | `A-****` | `h_515a806e…` (hash) |
| THREAT_HUNTER | S-0457 | `A-1123` | `+34 6…` (en claro) |

Importante: sin `USE SECONDARY ROLES NONE` el analista hereda los roles secundarios del
usuario (p. ej. SOC_ADMIN → THREAT_HUNTER) y lo ve todo en claro.

**Checkpoint** (ejecutar con cada rol)

```sql
SELECT CURRENT_ROLE() AS rol, store_id, agent_id, msisdn
FROM SECURITY_LAKE.GOLD.V_SIM_RIESGO_AGENTES LIMIT 2;
```

---

## Limpieza (opcional, al terminar)

```sql
USE ROLE SOC_ADMIN;
DROP VIEW IF EXISTS SECURITY_LAKE.GOLD.V_SIM_RIESGO_AGENTES;
DROP MASKING POLICY IF EXISTS SECURITY_LAKE.GOVERNANCE.MASK_AGENT_ID;
```
