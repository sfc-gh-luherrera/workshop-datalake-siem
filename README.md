# Workshop: Security Data Lake en Snowflake

Laboratorio práctico para equipos de seguridad y SOC. Parte de logs almacenados en S3 (o en un
stage interno de Snowflake) y llega a detecciones en SQL, hunting sobre un año de datos, modelos
de anomalías y fraude, triage con IA, un agente conversacional, un dashboard y gobierno del dato,
todo dentro de Snowflake.

La guía paso a paso está en [`docs/guia_evaluador.md`](docs/guia_evaluador.md).

## Contenido

| Ruta | Qué es |
|---|---|
| `docs/guia_evaluador.md` | Guía para replicar el laboratorio, con resultados esperados y retos |
| `generator/` | Generador de logs sintéticos (13 meses) con incidentes sembrados |
| `sql/` | Scripts en orden de ejecución (`00` a `09`, y `99` para limpiar) |
| `sql/backup/` | Modelos ML de respaldo, por si no usas los prompts con Cortex Code |
| `prompts/` | Prompts guiados para Cortex Code (ML de anomalías, fraude SIM, enmascaramiento) |
| `streamlit/` | Dashboard SOC para Streamlit in Snowflake |
| `runbooks/` | Runbooks sintéticos que indexa Cortex Search |

Todos los datos son sintéticos.
