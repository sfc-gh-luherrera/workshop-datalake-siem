-- =====================================================================
-- 07 · IA: triage con LLM, runbooks con Cortex Search, agente y servidor MCP
-- Requisito: CORTEX_ENABLED_CROSS_REGION = 'AWS_EU' (residencia UE). Ver preparación.
-- =====================================================================
USE ROLE SOC_ADMIN;
USE WAREHOUSE SOC_WH;
USE SCHEMA SECURITY_LAKE.GOLD;

-- 1) Triage estructurado de alertas (8.5): JSON con esquema -> columnas consultables
UPDATE ALERTS SET triage = AI_COMPLETE(
  model => 'claude-sonnet-4-5',
  prompt => 'Eres analista SOC L2. Haz el triage de esta alerta en español, conciso. Alerta: '
            || TO_JSON(OBJECT_CONSTRUCT('detection', detection, 'entity', entity, 'event_time', event_time, 'details', details)),
  response_format => {'type': 'json', 'schema': {'type': 'object', 'properties': {
      'resumen': {'type': 'string'},
      'tactica_mitre': {'type': 'string'},
      'severidad': {'type': 'string', 'enum': ['baja', 'media', 'alta', 'critica']},
      'siguientes_pasos': {'type': 'array', 'items': {'type': 'string'}}},
    'required': ['resumen', 'tactica_mitre', 'severidad', 'siguientes_pasos']}})
WHERE triage IS NULL;

SELECT detection, entity, triage:severidad::STRING AS severidad, triage:tactica_mitre::STRING AS mitre,
       triage:resumen::STRING AS resumen, triage:siguientes_pasos AS pasos
FROM ALERTS ORDER BY event_time;

-- 2) Runbooks indexados con Cortex Search (RAG sobre procedimientos)
CREATE OR REPLACE FILE FORMAT SECURITY_LAKE.BRONZE.FF_WHOLE_FILE
  TYPE = CSV FIELD_DELIMITER = NONE RECORD_DELIMITER = NONE ESCAPE_UNENCLOSED_FIELD = NONE;
CREATE OR REPLACE TABLE RUNBOOKS AS
SELECT SPLIT_PART(METADATA$FILENAME, '/', -1) AS runbook,
       REGEXP_SUBSTR($1, '^# (.*)', 1, 1, 'me', 1) AS title, $1 AS content
FROM @SECURITY_LAKE.BRONZE.S3_LOGS/runbooks/ (FILE_FORMAT => 'SECURITY_LAKE.BRONZE.FF_WHOLE_FILE');

CREATE OR REPLACE CORTEX SEARCH SERVICE RUNBOOK_SEARCH
  ON content ATTRIBUTES title
  WAREHOUSE = SOC_WH TARGET_LAG = '1 day'
  AS SELECT runbook, title, content FROM RUNBOOKS;

SELECT r.value:title::STRING AS title
FROM TABLE(FLATTEN(PARSE_JSON(SNOWFLAKE.CORTEX.SEARCH_PREVIEW('SECURITY_LAKE.GOLD.RUNBOOK_SEARCH',
  '{"query": "¿Cómo gestionamos el último caso de túnel DNS?", "columns": ["title"], "limit": 2}')):results)) r;

-- 3) Vista semántica para preguntas en lenguaje natural (8.3, 8.4)
CREATE OR REPLACE SEMANTIC VIEW SOC_SEMANTIC_VIEW
  TABLES (
    alerts AS SECURITY_LAKE.GOLD.ALERTS PRIMARY KEY (alert_id) COMMENT = 'Cola de alertas del SOC generadas por las detecciones',
    net AS SECURITY_LAKE.SILVER.NETWORK_ACTIVITY COMMENT = 'Actividad de red: NetFlow y firewall/VPN normalizados',
    auth AS SECURITY_LAKE.SILVER.AUTH_ACTIVITY COMMENT = 'Autenticaciones de Windows/AD y actividad de Office 365'
  )
  FACTS (
    net.bytes_out AS bytes_out COMMENT = 'Bytes salientes del flujo'
  )
  DIMENSIONS (
    alerts.detection AS detection COMMENT = 'Tipo de detección: brute_force_success, dns_tunnel, exfiltration, o365_mass_download, ioc_hit, source_silent',
    alerts.entity AS entity COMMENT = 'Entidad afectada (host, usuario@ip, host -> dominio)',
    alerts.alert_time AS event_time COMMENT = 'Momento del evento que originó la alerta',
    alerts.status AS status COMMENT = 'Estado de la alerta',
    alerts.severity AS triage:severidad::STRING COMMENT = 'Severidad asignada en el triage con IA',
    net.src_ip AS src_ip COMMENT = 'IP origen',
    net.dst_ip AS dst_ip COMMENT = 'IP destino',
    net.dst_port AS dst_port COMMENT = 'Puerto destino',
    net.net_source AS source COMMENT = 'Fuente: netflow o fw',
    net.device AS device COMMENT = 'Firewall o VPN que emitió el evento',
    net.action AS action COMMENT = 'Acción del firewall: allow o deny',
    net.net_time AS event_time COMMENT = 'Momento del flujo',
    net.net_unit AS unit COMMENT = 'Unidad de negocio (UES, UBR, UDE)',
    auth.user_name AS user_name COMMENT = 'Usuario',
    auth.auth_src_ip AS src_ip COMMENT = 'IP origen de la autenticación',
    auth.activity AS activity COMMENT = 'logon_success, logon_failure, special_privileges u operación de O365',
    auth.auth_source AS source COMMENT = 'Fuente: ad u o365',
    auth.auth_time AS event_time COMMENT = 'Momento de la autenticación'
  )
  METRICS (
    alerts.alert_count AS COUNT(alert_id) COMMENT = 'Número de alertas',
    net.total_bytes_out AS SUM(net.bytes_out) COMMENT = 'Total de bytes salientes',
    net.flow_count AS COUNT(net.src_ip) COMMENT = 'Número de flujos o conexiones',
    auth.failed_logons AS COUNT_IF(auth.activity = 'logon_failure') COMMENT = 'Inicios de sesión fallidos',
    auth.auth_events AS COUNT(auth.user_name) COMMENT = 'Eventos de autenticación'
  )
  COMMENT = 'Modelo semántico del SOC para preguntas en lenguaje natural';
-- Verified queries (8.4): añadir en Snowsight > AI & ML > Cortex Analyst > SOC_SEMANTIC_VIEW
-- tras validar 3-5 preguntas de hunting habituales.

-- 4) Agente SOC (8.5) con analista (texto a SQL) y runbooks (búsqueda)
CREATE OR REPLACE AGENT SOC_AGENT
  COMMENT = 'Asistente SOC: hunting en lenguaje natural y runbooks'
  FROM SPECIFICATION $$
models:
  orchestration: auto
instructions:
  response: "Responde en español, conciso, citando entidades (IP, usuario, dominio) y fechas. Muestra la SQL usada."
  orchestration: "Usa soc_analyst para preguntas sobre alertas, tráfico y autenticaciones. Usa runbooks para procedimientos de respuesta."
tools:
  - tool_spec:
      type: "cortex_analyst_text_to_sql"
      name: "soc_analyst"
      description: "Alertas del SOC, actividad de red (NetFlow, firewall) y autenticaciones (AD, Office 365)"
  - tool_spec:
      type: "cortex_search"
      name: "runbooks"
      description: "Runbooks de respuesta a incidentes del SOC"
tool_resources:
  soc_analyst:
    semantic_view: "SECURITY_LAKE.GOLD.SOC_SEMANTIC_VIEW"
    execution_environment:
      type: warehouse
      warehouse: "SOC_WH"
  runbooks:
    name: "SECURITY_LAKE.GOLD.RUNBOOK_SEARCH"
    max_results: 3
$$;

-- Prueba por SQL (también disponible en Snowflake Intelligence y por API REST)
WITH r AS (SELECT TRY_PARSE_JSON(SNOWFLAKE.CORTEX.DATA_AGENT_RUN('SECURITY_LAKE.GOLD.SOC_AGENT',
  '{"messages":[{"role":"user","content":[{"type":"text","text":"¿Qué alertas de severidad crítica hay y qué entidad afectan?"}]}]}')) AS j)
SELECT f.value:text::STRING AS respuesta FROM r, LATERAL FLATTEN(r.j:content) f WHERE f.value:type::STRING = 'text';

-- 5) Servidor MCP gestionado (8.1, 5.4): expone el agente a clientes MCP externos
CREATE OR REPLACE MCP SERVER SOC_MCP
  FROM SPECIFICATION $$
  tools:
    - title: "Asistente SOC"
      name: "soc_agent"
      type: "CORTEX_AGENT_RUN"
      identifier: "SECURITY_LAKE.GOLD.SOC_AGENT"
      description: "Preguntas de hunting y respuesta a incidentes sobre el security data lake"
  $$;
-- URL: https://<account_url>/api/v2/databases/SECURITY_LAKE/schemas/GOLD/mcp-servers/SOC_MCP
-- OAuth para el cliente MCP: ver la documentación de Snowflake sobre servidores MCP gestionados

-- 6) Gobierno de la IA (8.7): el analista solo usa lo que su rol permite
GRANT USAGE ON AGENT SOC_AGENT TO ROLE SOC_ANALYST;
GRANT USAGE ON MCP SERVER SOC_MCP TO ROLE SOC_ANALYST;
GRANT USAGE ON CORTEX SEARCH SERVICE RUNBOOK_SEARCH TO ROLE SOC_ANALYST;
GRANT SELECT ON SEMANTIC VIEW SOC_SEMANTIC_VIEW TO ROLE SOC_ANALYST;
GRANT SELECT ON TABLE ALERTS TO ROLE SOC_ANALYST;
GRANT SELECT ON ALL DYNAMIC TABLES IN SCHEMA SECURITY_LAKE.SILVER TO ROLE SOC_ANALYST;

-- 7) Coste de la IA (8.6): latencia de ACCOUNT_USAGE ~1-3 h
SELECT function_name, model_name, SUM(token_credits) AS credits, SUM(tokens) AS tokens
FROM SNOWFLAKE.ACCOUNT_USAGE.CORTEX_FUNCTIONS_USAGE_HISTORY
WHERE start_time >= DATEADD('day', -7, CURRENT_TIMESTAMP())
GROUP BY ALL ORDER BY credits DESC;
