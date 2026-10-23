"""Dashboard SOC (Streamlit in Snowflake) sobre SECURITY_LAKE.GOLD."""
import streamlit as st
from snowflake.snowpark.context import get_active_session

st.set_page_config(page_title="SOC · Security Data Lake", layout="wide")
session = get_active_session()


@st.cache_data(ttl=300)
def q(sql):
    return session.sql(sql).to_pandas()


st.title("SOC · Security Data Lake")

alerts = q("""
    SELECT detection, entity, event_time, status, unit,
           triage:severidad::STRING AS severidad, triage:tactica_mitre::STRING AS mitre,
           triage:resumen::STRING AS resumen
    FROM SECURITY_LAKE.GOLD.ALERTS ORDER BY event_time DESC
""")

c1, c2, c3, c4 = st.columns(4)
c1.metric("Alertas", len(alerts))
c2.metric("Críticas", int((alerts["SEVERIDAD"] == "critica").sum()))
c3.metric("Nuevas", int((alerts["STATUS"] == "NEW").sum()))
c4.metric("Tipos de detección", alerts["DETECTION"].nunique())

sev = st.multiselect("Severidad", ["critica", "alta", "media", "baja"], default=["critica", "alta"])
view = alerts[alerts["SEVERIDAD"].isin(sev)] if sev else alerts
st.dataframe(view, use_container_width=True)

left, right = st.columns(2)
with left:
    st.subheader("Alertas por detección")
    st.bar_chart(alerts.groupby("DETECTION").size())
with right:
    st.subheader("Tráfico saliente diario (NetFlow)")
    traffic = q("""
        SELECT event_time::DATE AS dia, SUM(bytes_out) / 1e9 AS gb
        FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
        WHERE source = 'netflow' AND event_time >= '2026-09-01'
        GROUP BY 1 ORDER BY 1
    """)
    st.line_chart(traffic, x="DIA", y="GB")

st.subheader("Salud de fuentes")
st.dataframe(q("SELECT * FROM SECURITY_LAKE.GOLD.DET_SOURCE_SILENT"), use_container_width=True)

st.subheader("Cola de investigación SIM swap")
st.dataframe(q("""
    SELECT store_id, agent_id, COUNT(*) AS solicitudes_riesgo, ROUND(AVG(fraud_score), 2) AS score_medio
    FROM SECURITY_LAKE.GOLD.SIM_SCORED WHERE fraud_score > 0.5
    GROUP BY ALL ORDER BY solicitudes_riesgo DESC LIMIT 10
"""), use_container_width=True)
