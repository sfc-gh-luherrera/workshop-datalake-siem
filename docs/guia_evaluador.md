# Guía del evaluador · Security Data Lake en Snowflake

En este laboratorio vas a construir, en tu propia cuenta de Snowflake, un data lake de seguridad
sobre logs que están en un bucket de S3 (o, si no tienes AWS a mano, en un stage interno de
Snowflake). Partirás de ficheros comprimidos de DNS, NetFlow, IDS, Active Directory, firewall,
Office 365 y solicitudes de cambio de SIM, y terminarás con detecciones en SQL, hunting sobre un
año de datos, un modelo de anomalías, un modelo de fraude, triage de alertas con IA, un agente
conversacional, un dashboard y políticas de gobierno que deciden quién ve qué.

Todos los datos son sintéticos. Los genera un script incluido en el repositorio, que siembra a
propósito varios incidentes de seguridad para que tengas algo concreto que encontrar. El
laboratorio completo lleva entre dos y tres horas, más el tiempo de preparación del entorno.

La guía está pensada para perfiles técnicos de seguridad que nunca han trabajado con Snowflake.
Cada vez que aparece un concepto nuevo, lo explicamos brevemente en un recuadro.

> **Snowsight** es la interfaz web de Snowflake. Desde ella se escribe SQL, se exploran los
> objetos, se gestionan permisos y se ejecutan aplicaciones y agentes. Salvo la generación de los
> datos, todo el laboratorio se hace desde el navegador.

## Contenido

1. Requisitos previos
2. Paso 0 · Obtener el código y generar los datos
3. Paso 1 · Preparar la cuenta
4. Módulo 1 · La plataforma: navegación, cómputo y roles
5. Módulo 2 · Los logs en el bucket: explorar, consultar en sitio y cargar
6. Módulo 3 · Normalización y modelo por capas
7. Módulo 4 · Detección y hunting sobre un año
8. Módulo 5 · Fraude SIM swap con ML
9. Módulo 6 · IA para el SOC: triage, runbooks, agente, MCP y dashboard
10. Módulo 7 · Gobierno y auditoría
11. Lectura opcional · Coexistencia con Splunk
12. Problemas frecuentes
13. Limpieza
14. Solucionario: incidentes sembrados

---

## Requisitos previos

| Elemento | Detalle |
|---|---|
| Cuenta de Snowflake | Edición Enterprise o superior. Se recomienda una región de AWS en la UE (por ejemplo `eu-west-3`, París, o `eu-central-1`, Frankfurt). Si no tienes cuenta, puedes abrir una de prueba. |
| Rol | `ACCOUNTADMIN` para los scripts `00` y `01`, que crean roles, la integración con S3 y permisos de cuenta. El resto se ejecuta con el rol `SOC_ADMIN` que crea el propio laboratorio. |
| Cortex (IA) | Los modelos de lenguaje tienen que estar disponibles en tu región o tener activada la inferencia entre regiones. Lo comprobamos en el paso 1. |
| Cortex Code | El asistente de IA de Snowsight, para construir los modelos de ML y el enmascaramiento con los prompts de `prompts/`. Si no lo tienes disponible, cada paso tiene un script alternativo. |
| AWS (opcional) | Permisos para crear un bucket de S3, una política y un rol IAM. Si no tienes AWS, usarás un stage interno y el resultado es el mismo. |
| Equipo local | Python 3.10 o superior y `git`. Para la opción sin AWS, una conexión de Snowflake configurada (por ejemplo con Snowflake CLI, en `~/.snowflake/connections.toml`). |

El consumo es pequeño: el conjunto de datos ocupa unos 50 MB comprimidos y todas las consultas se
ejecutan en un warehouse XSMALL en pocos segundos. Aun así, el laboratorio crea un resource monitor
que limita el gasto a 50 créditos.

---

## Paso 0 · Obtener el código y generar los datos

Clona o descarga el repositorio del laboratorio. Su estructura es esta:

| Ruta | Qué es |
|---|---|
| `generator/` | Generador de logs sintéticos y script de subida a un stage interno |
| `sql/` | Scripts de preparación y de cada módulo, numerados en orden de ejecución |
| `sql/demo_snippets/` | Las consultas de cada paso, sueltas, para pegarlas en Snowsight |
| `sql/backup/` | Script de respaldo que crea los modelos de ML si no usas Cortex Code |
| `prompts/` | Prompts para Cortex Code: ML de anomalías, ML de fraude y enmascaramiento |
| `streamlit/` | Código del dashboard SOC |
| `runbooks/` | Runbooks sintéticos que consultará la IA |

### El conjunto de datos

El script `generator/generate_logs.py` simula trece meses de actividad (395 días, del 22 de
septiembre de 2025 al 21 de octubre de 2026) en una organización con tres unidades de negocio:
UES (España), UDE (Alemania) y UBR (Brasil). Usa una semilla aleatoria fija (`SEED = 42`), así
que siempre produce exactamente los mismos ficheros y tus resultados coincidirán con los de esta
guía.

Genera siete fuentes, cada una en el formato que tendría en la vida real:

| Fuente | Formato | Volumen diario aproximado | Qué simula |
|---|---|---|---|
| `dns` | JSON por líneas | 2.000 consultas | Consultas de los hosts internos al resolvedor DNS |
| `netflow` | JSON por líneas | 2.000 flujos | Conexiones de red de los hosts internos hacia Internet |
| `suricata` | JSON (EVE) | 60 alertas | Alertas de un IDS de red |
| `ad` | JSON | 600 eventos | Inicios de sesión de Windows y Active Directory (4624, 4625, 4672) |
| `fw` | Syslog en texto | 1.200 líneas | Firewalls y VPN de cuatro fabricantes distintos |
| `o365` | JSON | 300 eventos | Auditoría de Office 365 (accesos y descargas de ficheros) |
| `sim` | CSV | 150 solicitudes | Solicitudes de cambio de SIM, portabilidad y activación en tiendas |

Además, genera un fichero de indicadores de compromiso (`ioc/ioc_feed.csv.gz`) con 55 entradas y
copia los runbooks de `runbooks/` para que la IA pueda consultarlos. Cada fuente se escribe en un
fichero gzip por día con la ruta `<fuente>/AAAA/MM/DD/<fuente>_AAAAMMDD.<extensión>.gz`, que es la
organización habitual de un bucket de logs y la que permite consultar o cargar solo un mes o un
día. En total son unos 2,5 millones de eventos.

Sobre ese tráfico de fondo, el generador inserta varios incidentes. No te los contamos aquí para
que los encuentres tú; si te atascas, están al final, en el solucionario.

> **Stage.** En Snowflake, un *stage* es un puntero con nombre a una ubicación de ficheros. Puede
> ser *externo* (apunta a un bucket de S3, Azure o GCS que sigue siendo tuyo) o *interno*
> (Snowflake guarda los ficheros por ti). Sobre un stage se pueden listar ficheros, consultarlos
> directamente con SQL o cargarlos en tablas. En los dos casos, el laboratorio lo llama
> `SECURITY_LAKE.BRONZE.S3_LOGS`, así que los scripts posteriores no cambian.

### Opción A: con un bucket de S3 propio

1. Crea un bucket en la misma región que tu cuenta de Snowflake y bloquea el acceso público. En
   esta guía lo llamamos `<tu-bucket>`.
2. Crea una política IAM de lectura sobre el bucket, con escritura solo en la carpeta `exports/`
   (la usaremos para exportar resultados):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Effect": "Allow",
         "Action": ["s3:GetObject", "s3:GetObjectVersion"],
         "Resource": "arn:aws:s3:::<tu-bucket>/*" },
       { "Effect": "Allow",
         "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
         "Resource": "arn:aws:s3:::<tu-bucket>" },
       { "Effect": "Allow",
         "Action": ["s3:PutObject", "s3:DeleteObject"],
         "Resource": "arn:aws:s3:::<tu-bucket>/exports/*" }
     ]
   }
   ```

3. Crea un rol IAM con esa política. La política de confianza la completarás en el paso 1, cuando
   Snowflake te dé sus identificadores.
4. Genera los datos y súbelos (necesitas credenciales de AWS con permiso de escritura, por ejemplo
   con `aws configure`):

   ```bash
   cd generator
   pip install -r requirements.txt
   python generate_logs.py --upload --bucket <tu-bucket>
   ```

### Opción B: sin AWS, con un stage interno

Si no tienes AWS, genera los ficheros en disco y súbelos a Snowflake. El script de subida usa el
conector de Python de Snowflake, que se instala con el resto de dependencias:

```bash
cd generator
pip install -r requirements.txt
python generate_logs.py --local ./out
```

La subida (`upload_internal.py`) se hace después de crear el stage, en el paso 1.

En las dos opciones, el parámetro `--scale` permite multiplicar el volumen (por ejemplo,
`--scale 0.5` genera la mitad). Las cifras de esta guía corresponden a la escala por defecto.

---

## Paso 1 · Preparar la cuenta

Abre Snowsight, ve a Projects > Workspaces y crea un fichero SQL. En él irás pegando y ejecutando
los scripts del directorio `sql/`. Para ejecutar un script entero, pega su contenido y usa
"Run all"; para ejecutar una sola consulta, coloca el cursor en ella y pulsa Ctrl+Enter
(Cmd+Enter en Mac).

### 1.1 Comprobar Cortex

Como `ACCOUNTADMIN`, comprueba la región y que el modelo de lenguaje que usa el laboratorio
responde:

```sql
SELECT CURRENT_REGION(), CURRENT_VERSION();
SHOW PARAMETERS LIKE 'CORTEX_ENABLED_CROSS_REGION' IN ACCOUNT;
-- Opcional: limitar la inferencia de Cortex a regiones de la UE
ALTER ACCOUNT SET CORTEX_ENABLED_CROSS_REGION = 'AWS_EU';
SELECT AI_COMPLETE('claude-sonnet-4-5', 'di hola');
```

Si la última consulta falla porque el modelo no está disponible, cambia el modelo en
`sql/07_ai_triage.sql` por uno disponible en tu región.

### 1.2 Roles, warehouse y base de datos (`sql/00_admin_roles_wh.sql`)

Ejecuta el script `00` con `ACCOUNTADMIN`. Crea la base de datos `SECURITY_LAKE` con sus esquemas,
el warehouse `SOC_WH`, los roles `SOC_ADMIN`, `SOC_ANALYST` y `THREAT_HUNTER`, el resource monitor
`SOC_MONITOR` y los permisos necesarios, incluido `EXECUTE DATA METRIC FUNCTION`.

> **Base de datos y esquema.** Una *cuenta* de Snowflake contiene *bases de datos*, cada base de
> datos contiene *esquemas* y cada esquema contiene tablas, vistas y otros objetos. Aquí usamos
> `SECURITY_LAKE` con cuatro esquemas: `BRONZE` (los logs tal como llegan), `SILVER`
> (normalizados), `GOLD` (detecciones y alertas) y `GOVERNANCE` (políticas).

### 1.3 Conectar con los ficheros

**Opción A (S3).** Edita `sql/01_s3_integration_stage.sql` antes de ejecutarlo: sustituye
`<AWS_ACCOUNT_ID>` y el nombre del rol IAM en `STORAGE_AWS_ROLE_ARN`, y cambia
`workshop-datalake-siem` por `<tu-bucket>` en `STORAGE_ALLOWED_LOCATIONS` y en la `URL` del
stage. Ejecútalo con `ACCOUNTADMIN`. Después, obtén los identificadores que Snowflake usará para
asumir tu rol:

```sql
DESC INTEGRATION S3_SIEM_INT;
```

Copia `STORAGE_AWS_IAM_USER_ARN` y `STORAGE_AWS_EXTERNAL_ID` en la política de confianza del rol
IAM:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "AWS": "<STORAGE_AWS_IAM_USER_ARN>" },
    "Action": "sts:AssumeRole",
    "Condition": { "StringEquals": { "sts:ExternalId": "<STORAGE_AWS_EXTERNAL_ID>" } }
  }]
}
```

> **Storage integration.** Es el objeto que guarda la relación de confianza entre Snowflake y tu
> cuenta de AWS. En lugar de almacenar claves de acceso, Snowflake asume un rol IAM que tú
> controlas, presentando un identificador externo único. Puedes revocar el acceso en cualquier
> momento desde AWS quitando la política de confianza.

**Opción B (stage interno).** Ejecuta `sql/01b_internal_stage_rehearsal.sql`. Crea el stage
interno `S3_LOGS` con la misma estructura y los formatos de fichero. Después, desde tu equipo, sube
los ficheros generados:

```bash
python upload_internal.py --dir ./out --connection <tu-conexión>
```

**Comprobación.** En los dos casos, esta consulta debe listar ficheros:

```sql
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/dns/2026/10/;
```

### 1.4 Construir el resto del laboratorio (`sql/02` a `sql/08`)

Ejecuta en orden los scripts `02` a `05` con el rol `SOC_ADMIN`. Cargan la capa bronze,
construyen las capas silver y gold, crean las detecciones y preparan el hunting. En un warehouse
XSMALL tardan unos minutos cada uno.

A continuación ejecuta `sql/backup/ml_modelos_respaldo.sql` (alrededor de un minuto). Crea los dos
modelos de ML y sus resultados (`GOLD.EGRESS_ANOMALIES`, `GOLD.NET_ANOMALIES` y `GOLD.SIM_SCORED`).
En los módulos 4 y 5 los volverás a construir tú mismo con Cortex Code, con los mismos nombres;
este respaldo garantiza que los scripts siguientes tienen datos aunque algo falle. Tiene que ir
antes de `06` a `08`: `06` consulta el modelo de fraude, `07` y el dashboard leen sus resultados y
`08` enmascara `SIM_SCORED.msisdn`.

Por último, ejecuta `06` a `08`, que preparan la IA y aplican el gobierno. Los módulos que siguen
recorren lo que crean, explicando cada pieza y repitiendo sus consultas clave. El script `09` (clon
y Time Travel) y `sql/demo_snippets/share.sql` no forman parte de la preparación: los ejecutarás
en los módulos 4 y 3.

> **Cortex Code.** Es el asistente de IA de Snowflake para ingeniería de datos: recibe una
> petición en lenguaje natural, explora los objetos de la cuenta, escribe la SQL, la ejecuta con tu
> rol activo y explica el resultado. Cada fichero de `prompts/` tiene, por paso, el prompt que hay
> que pegar, el resultado esperado y una consulta de comprobación.

Si usas la opción A, en `sql/02_bronze_load.sql` puedes descomentar el bloque de la tabla externa
`DNS_EXT`; solo funciona con un stage externo.

---

## Módulo 1 · La plataforma: navegación, cómputo y roles

**Objetivo:** orientarte en Snowsight y entender cómo se separan almacenamiento, cómputo y
permisos.

### 1.1 Navegación

En la página de inicio de Snowsight, recorre el menú izquierdo: Projects, Ingestion,
Transformation, AI & ML, Monitoring, Apps, Catalog, Governance & security, Compute y Admin. Todo
es un servicio gestionado: no hay servidores, parches ni índices que operar. Los datos se cifran
en reposo con AES-256 y en tránsito con TLS.

Debería verse así:

### 1.2 Cómputo elástico

En Compute > Warehouses abre `SOC_WH`. Es de tamaño XSMALL, se suspende automáticamente tras 60
segundos sin uso y puede crecer de uno a tres clústeres si hay muchas consultas a la vez.

> **Warehouse.** En Snowflake, un *virtual warehouse* no es un almacén de datos, sino un clúster
> de cómputo que ejecuta las consultas. Los datos están guardados aparte, así que se pueden tener
> varios warehouses de distintos tamaños leyendo los mismos datos sin copiarlos. Se paga por
> segundo mientras el warehouse está encendido, y se apaga solo cuando nadie lo usa.

En un SOC esto permite aislar cargas de trabajo. Piensa en el turno de mañana: el equipo de
hunting lanza una búsqueda sobre doce meses de NetFlow justo cuando corre la tarea horaria de
detecciones. Con un warehouse para cada uno (por ejemplo, `DETECT_WH` pequeño para las tasks y
`HUNT_WH` más grande y encendido solo cuando alguien caza), ninguno frena al otro. El laboratorio
usa un único `SOC_WH` para simplificar.

Hay dos formas de crecer. *Escalar hacia arriba* (de XSMALL a LARGE) acelera una consulta pesada; lo
harás en el módulo 4. *Escalar hacia fuera* (multi-cluster, de uno a tres clústeres en `SOC_WH`)
no acelera ninguna consulta, sino que absorbe la concurrencia cuando muchos analistas consultan a
la vez. El multi-cluster requiere la edición Enterprise o superior.

> **Auto-suspend y facturación por segundo.** Un warehouse se suspende solo tras el tiempo de
> inactividad configurado (aquí, 60 segundos) y se reanuda solo con la siguiente consulta. Se
> factura por segundo, con un mínimo de 60 segundos cada vez que arranca.

El guardarraíl de coste es el resource monitor `SOC_MONITOR`, que verás en el módulo 7: si alguien
deja un warehouse grande encendido, avisa al 80 % del presupuesto y lo suspende al 100 %.

**Reto.** Sin ejecutarlo, escribe el `CREATE WAREHOUSE` de un `HUNT_WH` de tamaño LARGE que se
suspenda tras 60 segundos y arranque suspendido. Una búsqueda de 5 segundos sobre ese warehouse
parado, ¿cuántos segundos de cómputo factura?

### 1.3 Roles

El laboratorio tiene tres roles: `SOC_ANALYST`, que ve las capas SILVER y GOLD; `THREAT_HUNTER`,
que además ve los logs originales en BRONZE; y `SOC_ADMIN`, que administra el entorno. Cambia de
rol en el selector de la esquina inferior izquierda y observa cómo cambian los objetos visibles en
Catalog.

> **Roles.** En Snowflake los permisos nunca se dan directamente a una persona, sino a un *rol*, y
> el usuario trabaja con el rol que tiene activo. Un usuario puede tener además *roles
> secundarios*, cuyos permisos se suman a los del rol principal. Esto será importante en el
> módulo de gobierno.

**Reto.** Con el rol `SOC_ANALYST`, intenta consultar `SECURITY_LAKE.BRONZE.DNS_RAW`. ¿Qué error
obtienes y por qué?

---

## Módulo 2 · Los logs en el bucket: explorar, consultar en sitio y cargar

**Objetivo:** ver que Snowflake trabaja sobre los ficheros que ya tienes, sin moverlos, y
aprender las dos formas de usarlos: consultarlos en sitio o cargarlos.

### 2.1 Explorar el stage desde la interfaz

En Catalog > Database Explorer > `SECURITY_LAKE` > `BRONZE` > Stages, abre `S3_LOGS`. Verás una
carpeta por fuente: `ad`, `dns`, `fw`, `ioc`, `netflow`, `o365`, `runbooks`, `sim` y `suricata`.

Entra en `dns/2026/10/` y fíjate en el tamaño de los ficheros de cada día. ¿Hay alguno que
destaque? Apunta las fechas: volverás a ellas.

### 2.2 Cómo se conecta

Si usas S3, revisa de nuevo la integración y localiza los campos `STORAGE_AWS_ROLE_ARN` y
`STORAGE_AWS_EXTERNAL_ID`:

```sql
USE ROLE SOC_ADMIN;
DESC INTEGRATION S3_SIEM_INT;
```

### 2.3 Listar ficheros con SQL

```sql
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/dns/2026/10/;
```

`LIST` devuelve los ficheros de esa carpeta con su tamaño y su fecha de modificación, igual que lo
haría la consola de AWS, pero desde SQL.

### 2.4 Inventario con SQL

```sql
USE SCHEMA SECURITY_LAKE.BRONZE;
SELECT SPLIT_PART(relative_path,'/',1) AS fuente,
       COUNT(*) AS ficheros,
       ROUND(SUM(size)/1024/1024,1) AS mb
FROM DIRECTORY(@S3_LOGS)
GROUP BY 1 ORDER BY mb DESC;
```

> **Directory table.** Un stage puede tener asociada una tabla de directorio, que es un catálogo
> de sus ficheros (ruta, tamaño, fecha) consultable con SQL normal mediante `DIRECTORY(@stage)`.

**Resultado esperado:** 395 ficheros diarios por fuente, uno por día durante trece meses; netflow
es la fuente más pesada, con unos 22 MB.

### 2.5 Consultar en sitio, sin cargar

Consulta directamente los ficheros DNS de uno de los días que te llamaron la atención en el paso
2.1 (aquí, el 15 de octubre), filtrando las consultas con nombres muy largos:

```sql
SELECT $1:ts::TIMESTAMP_NTZ AS ts, $1:client_ip::STRING AS host,
       $1:query::STRING AS query, METADATA$FILENAME AS fichero
FROM @S3_LOGS/dns/2026/10/15/ (FILE_FORMAT => 'FF_JSON')
WHERE LENGTH($1:query::STRING) > 40
LIMIT 20;
```

> **Consultar un stage.** Snowflake puede leer ficheros directamente desde un stage, sin
> cargarlos en una tabla. `$1` representa el contenido de cada línea, la notación `$1:campo`
> extrae un campo del JSON y `::TIPO` convierte el valor a un tipo de dato. El *file format*
> `FF_JSON` le indica a Snowflake cómo interpretar los ficheros (en este caso, JSON comprimido con
> gzip).

**Para pensar:** ¿qué tienen en común los nombres consultados y qué técnica de ataque sugieren?

### 2.6 Cargar con COPY

```sql
CREATE OR REPLACE TABLE DNS_RAW_DEMO (raw VARIANT, src_file STRING,
                                      loaded_at TIMESTAMP_LTZ DEFAULT CURRENT_TIMESTAMP());
COPY INTO DNS_RAW_DEMO (raw, src_file)
  FROM (SELECT $1, METADATA$FILENAME FROM @S3_LOGS/dns/2026/10/)
  FILE_FORMAT = (FORMAT_NAME = 'FF_JSON');
```

> **VARIANT y COPY INTO.** `VARIANT` es un tipo de columna que guarda JSON (u otros datos
> semiestructurados) tal cual, sin definir antes su esquema, y que después se consulta con la
> misma notación `raw:campo`. `COPY INTO` es el comando de carga masiva desde un stage a una
> tabla.

**Resultado esperado:** 21 ficheros en estado `LOADED` y ningún error. Ejecuta el `COPY` otra vez:
no carga nada, porque `COPY` recuerda qué ficheros ha cargado ya y por tanto es idempotente. La
columna `src_file` guarda el fichero de origen de cada fila, lo que da trazabilidad hasta el
objeto del bucket.

Consulta el registro de cargas:

```sql
SELECT file_name, row_count, error_count, status, last_load_time
FROM TABLE(INFORMATION_SCHEMA.COPY_HISTORY(TABLE_NAME=>'DNS_RAW_DEMO',
     START_TIME=>DATEADD(hour,-1,CURRENT_TIMESTAMP())));
```

En producción hay tres formas habituales de usar los ficheros de un bucket: un `COPY` programado
con una task; Snowpipe con auto-ingest, que carga cada fichero nuevo en cuanto S3 lo notifica; o
tablas externas e Iceberg, que consultan los ficheros sin copiarlos.

La elección depende de cuánta latencia tolera cada fuente:

| Fuente del SOC | Cómo llega | Mecanismo | Latencia típica |
|---|---|---|---|
| Logs de firewall exportados cada noche a S3 | Ficheros diarios | `COPY INTO` programado con una task (`LOAD_DNS_DAILY` en el script `02`) | horas |
| Logs de proxy o VPN que caen en S3 cada pocos minutos | Ficheros pequeños y continuos | Snowpipe con auto-ingest | minutos |
| Telemetría de EDR publicada en Kafka | Mensajes, no ficheros | Snowpipe Streaming con el conector de Kafka para Snowflake | segundos |

> **Snowpipe y Snowpipe Streaming.** *Snowpipe* es un servicio de carga continua sin warehouse: S3
> notifica cada fichero nuevo y Snowflake lo carga con el mismo `COPY`. *Snowpipe Streaming* no
> trabaja con ficheros, sino con filas: un cliente (por ejemplo, el conector de Kafka) escribe los
> eventos directamente en la tabla y quedan consultables en segundos.

Abre `sql/02_bronze_load.sql` y fíjate en cómo está escrita la carga para que sea robusta: un
`COPY` por fuente con un `PATTERN` explícito, nunca `FORCE = TRUE` (los metadatos de carga evitan
duplicados durante 64 días), un tope de 15 minutos por sentencia con
`STATEMENT_TIMEOUT_IN_SECONDS = 900` y un bloque final con `LOAD_HISTORY` que indica qué fuente
tiene ficheros pendientes o con errores. Si algo falla, se relanza solo el `COPY` de esa fuente.
Cada fila guarda `METADATA$FILENAME` en `src_file`, así que siempre puedes volver al objeto exacto
del bucket.

### 2.7 La capa bronze completa

El script `02` ya cargó todas las fuentes. Comprueba los volúmenes:

```sql
SELECT 'dns' t, COUNT(*) FROM DNS_RAW UNION ALL SELECT 'netflow', COUNT(*) FROM NETFLOW_RAW
UNION ALL SELECT 'fw', COUNT(*) FROM FW_RAW UNION ALL SELECT 'ad', COUNT(*) FROM AD_RAW
UNION ALL SELECT 'o365', COUNT(*) FROM O365_RAW UNION ALL SELECT 'sim', COUNT(*) FROM SIM_REQUESTS
UNION ALL SELECT 'suricata', COUNT(*) FROM SURICATA_RAW UNION ALL SELECT 'ioc', COUNT(*) FROM IOC;
```

**Resultado esperado:** unos 2,5 millones de eventos: 793.040 de DNS, 790.050 de NetFlow, 473.566
de firewall, 237.062 de Active Directory, 119.000 de Office 365, 59.325 solicitudes SIM, 23.701
alertas de Suricata y 55 indicadores de compromiso.

**Reto.** Tienes un archivo de CloudTrail de dos años en S3 que consultas dos veces al mes. ¿Lo
cargarías o lo consultarías en sitio? Las dos respuestas son válidas: consultarlo en sitio evita
duplicar el almacenamiento y cargarlo hace las consultas más rápidas. Se decide fuente a fuente.

**Reto.** Adapta la consulta del paso 2.5 para contar, por día de octubre, cuántas consultas DNS
tienen más de 40 caracteres, leyendo los ficheros en sitio.

**Reto.** Ejecuta el bloque de verificación del final de `sql/02_bronze_load.sql`. ¿Qué fuente
tiene ficheros pendientes o con errores? Ejecuta otra vez el `COPY` de `DNS_RAW` del script: ¿cuántas
filas carga y por qué?

**Reto.** Clasifica estas fuentes por mecanismo de ingesta (`COPY` programado, Snowpipe o Snowpipe
Streaming): auditoría diaria de Office 365 exportada a S3, alertas de EDR en un topic de Kafka y
logs de proxy que se escriben en S3 cada cinco minutos.

---

## Módulo 3 · Normalización y modelo por capas

**Objetivo:** entender cómo se convierten logs heterogéneos en un modelo común que se mantiene
solo (script `sql/03_silver_normalize.sql`).

Los logs en JSON se guardan en columnas `VARIANT` y se consultan con rutas como
`raw:alert.signature`, mientras que el syslog de los firewalls es texto libre que se descompone
con expresiones regulares (`REGEXP_SUBSTR`) dentro de la tabla `NETWORK_ACTIVITY`.

Las capas tienen un papel claro. BRONZE conserva los logs intactos, lo que permite el análisis
forense. SILVER los normaliza siguiendo el modelo OCSF (Open Cybersecurity Schema Framework).
GOLD contiene las detecciones y las alertas. Snowflake no trae un modelo de datos de seguridad
propio: se adopta un estándar como OCSF, implementado como vistas o dynamic tables.

### 3.1 Dynamic tables y linaje

En Catalog > `SILVER` > Dynamic tables, abre `NETWORK_ACTIVITY` y revisa la pestaña Graph.

> **Dynamic table.** Es una tabla definida por una consulta SQL que Snowflake mantiene
> actualizada automáticamente. En lugar de escribir un proceso ETL con un orquestador, se declara
> cuánto retraso se tolera con `TARGET_LAG` (aquí, una hora) y Snowflake decide cuándo refrescar y
> procesa solo los datos nuevos.

La pestaña Lineage muestra el linaje de BRONZE a SILVER y a GOLD, a nivel de tabla y de columna.

### 3.2 Calidad del dato

La pestaña Data quality muestra las comprobaciones de calidad asociadas a la tabla: cuentan los
nulos de `EVENT_TIME` y `SRC_IP` cada vez que la tabla cambia.

> **Data Metric Functions (DMF).** Son funciones de calidad de datos (número de nulos, de
> duplicados, frescura, etc.) que se asocian a una tabla y que Snowflake ejecuta de forma
> programada o cada vez que la tabla cambia, guardando el histórico de resultados.

Si las comprobaciones aparecen sin resultado ("No checks"), la tabla aún no se ha refrescado desde
que se asociaron. Fuerza un refresco:

```sql
ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.NETWORK_ACTIVITY REFRESH;
```

### 3.3 Reproceso y ciclo de vida

Si cambia un parser, basta con redefinir la dynamic table para que recalcule todo el histórico a
partir de los datos originales de BRONZE. Para el ciclo de vida, el script aplica la política
`SLP_RAW_1Y_COOL`, que mantiene los datos consultables durante un año y después los archiva en
almacenamiento COOL durante cinco años. La política tarda unas 24 horas en ejecutarse por primera
vez.

> **Storage lifecycle policy.** Es una política que Snowflake aplica automáticamente a las filas
> de una tabla según su antigüedad, ya sea para borrarlas o para moverlas a un almacenamiento de
> archivo más barato.

Al final de la sección de retención, el script `03` deja comentada una variante COLD,
`SLP_RAW_90D_COLD`, pensada para logs que pasado un tiempo solo se piden por un requerimiento legal
o un análisis forense. COLD cuesta aproximadamente una cuarta parte de COOL, pero exige un mínimo de
180 días en archivo, solo está disponible en AWS y GCP y la recuperación puede tardar hasta 48
horas. Lo archivado no se consulta directamente: se restaura a una tabla nueva con
`CREATE TABLE ... FROM ARCHIVE OF ...` y un `WHERE` obligatorio. No la ejecutes sobre `DNS_RAW`: el
nivel de archivo de una tabla no se puede cambiar una vez asignado.

### 3.4 Compartir IOC con otro equipo

Imagina que el CSIRT del grupo, o el SOC de otro país, quiere ver hoy las coincidencias con IOC que
ha encontrado tu SOC. En lugar de exportar un CSV, se publica una vista segura con solo los
agregados por indicador y se comparte en vivo. Ejecuta `sql/demo_snippets/share.sql` (unos 7
segundos; la parte del share requiere `ACCOUNTADMIN`):

```sql
USE ROLE SOC_ADMIN;
CREATE OR REPLACE SECURE VIEW SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE AS
SELECT indicator, class, unit, MAX(confidence) AS confidence, COUNT(*) AS hits,
       COUNT(DISTINCT src_ip) AS hosts_afectados, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.GOLD.DET_IOC_HITS GROUP BY indicator, class, unit;

USE ROLE ACCOUNTADMIN;
CREATE SHARE IF NOT EXISTS SOC_IOC_SHARE COMMENT = 'IOC detectados por el SOC';
GRANT USAGE ON DATABASE SECURITY_LAKE TO SHARE SOC_IOC_SHARE;
GRANT USAGE ON SCHEMA SECURITY_LAKE.GOLD TO SHARE SOC_IOC_SHARE;
GRANT SELECT ON VIEW SECURITY_LAKE.GOLD.V_IOC_HITS_SHARE TO SHARE SOC_IOC_SHARE;
SHOW GRANTS TO SHARE SOC_IOC_SHARE;
```

> **Secure Data Sharing.** Un *share* da a otra cuenta de Snowflake acceso de solo lectura a objetos
> concretos, sin copiar datos ni mover ficheros: el consumidor consulta la versión actual y el
> proveedor puede revocarlo en cualquier momento. Una *secure view* oculta su definición al
> consumidor y es obligatoria para compartir vistas. Entre regiones o nubes distintas se usa un
> *listing*.

**Resultado esperado:** `SHOW GRANTS TO SHARE` muestra el uso de la base de datos y del esquema y el
`SELECT` sobre la vista, y nada más. Para añadir una cuenta consumidora se usaría
`ALTER SHARE SOC_IOC_SHARE ADD ACCOUNTS = <ORG>.<CUENTA>`; no lo hagas si no tienes una segunda
cuenta. Abre la vista en Catalog y revisa su propietario, su comentario y sus etiquetas: es lo que
vería el otro equipo al encontrarla.

**Reto.** ¿Por qué la vista compartida agrega por indicador y no incluye `src_ip`? ¿Qué tendrías que
cambiar para que el CSIRT solo viera las coincidencias de la unidad UES?

**Reto.** Abre `sql/03_silver_normalize.sql`, localiza cómo se extraen los campos del syslog de
firewall con `REGEXP_SUBSTR` y escribe una consulta sobre `BRONZE.FW_RAW` que extraiga el puerto
de destino (`dport=`) de cada línea.

---

## Módulo 4 · Detección y hunting sobre un año

**Objetivo:** escribir detecciones como código SQL, cruzar ciberinteligencia con un año de
eventos, construir con Cortex Code un modelo de ML que detecte anomalías, probar cambios de reglas
sobre un clon, deshacer errores con Time Travel y operar todo de forma programada (scripts
`sql/04_gold_detections.sql`, `sql/05_hunting_1y.sql` y `sql/09_timetravel_clone.sql`, y
`prompts/ml_anomalias_salida.md`).

### 4.1 Detecciones en SQL

Cada detección es una vista del esquema GOLD. Consulta una a una `DET_BRUTE_FORCE`,
`DET_BRUTE_FORCE_SUCCESS`, `DET_DNS_TUNNEL`, `DET_EXFIL` y `DET_O365_MASS_DOWNLOAD`, y abre su
definición en Catalog para ver cómo están escritas. `DET_BRUTE_FORCE_SUCCESS` no cuenta fallos:
busca una secuencia completa.

> **MATCH_RECOGNIZE.** Es una cláusula SQL estándar para buscar patrones en secuencias de filas
> ordenadas, de forma parecida a una expresión regular pero aplicada a eventos. Aquí busca "varios
> fallos, seguidos de un éxito, seguido de una elevación de privilegios" para el mismo usuario.

La detección de túnel DNS cierra la pista que encontraste en el bucket:

```sql
SELECT src_ip, query_domain, day, queries, distinct_labels,
       ROUND(avg_label_len,1) AS avg_len, unit
FROM SECURITY_LAKE.GOLD.DET_DNS_TUNNEL ORDER BY day;
```

**Para pensar:** ¿coinciden los días con los ficheros grandes que viste en el módulo 2?

### 4.2 Ciberinteligencia sobre doce meses

```sql
SELECT class, COUNT(*) AS hits, MIN(event_time) AS first_seen,
       MAX(event_time) AS last_seen, COUNT(DISTINCT src_ip) AS hosts
FROM SECURITY_LAKE.GOLD.DET_IOC_HITS GROUP BY class ORDER BY hits DESC;
```

Esta vista cruza los indicadores del feed con todo el año de eventos.

**Resultado esperado:** 3.040 coincidencias en DNS, 562 en autenticación y 50 en tráfico de red.
Fíjate en la columna `first_seen` de DNS: ¿cuántos meses atrás fue el primer contacto? Con una
retención de 30 a 90 días, ese caso no se podría ver.

Consulta también `GOLD.DET_SOURCE_SILENT`, que avisa cuando una fuente lleva más de doce horas sin
enviar logs. La ausencia de datos también es un incidente.

### 4.3 ML de anomalías con Cortex Code

La regla `DET_EXFIL` ha saltado. ¿Es el único caso o hay más subredes sacando datos de lo normal?
Vas a construir un modelo de detección de anomalías sin escribir SQL a mano. Abre Cortex Code con
el rol `SOC_ADMIN` y el warehouse `SOC_WH`, y pega uno a uno los cinco prompts de
`prompts/ml_anomalias_salida.md`. Después de cada uno, ejecuta la consulta de comprobación del
fichero.

| Prompt | Qué pide | Resultado esperado |
|---|---|---|
| 1 | Descubrir la tabla de red | `SILVER.NETWORK_ACTIVITY`; solo `netflow` trae `bytes_out` (unas 790.000 filas) |
| 2 | Serie diaria por subred /24 en la vista `GOLD.NET_DAILY_SUBNET`, materializada en `GOLD.EGRESS_DAILY_SUBNET` | 9 subredes, 395 días, 3.555 puntos; 3.510 anteriores al 17 de octubre |
| 3 | Entrenar `GOLD.NET_ANOMALY_MODEL` con los días anteriores al 17 de octubre | `Instance NET_ANOMALY_MODEL successfully created` |
| 4 | Detectar desde el 17 de octubre y guardar en `GOLD.EGRESS_ANOMALIES` | 45 filas y 2 anomalías |
| 5 | Explicar las columnas y dibujar observado frente a banda esperada | 10.20.8 se sale de la escala el 17 de octubre |

> **ML Functions.** Snowflake incluye funciones de machine learning que se entrenan y se usan con
> SQL, sin escribir código de ciencia de datos. Aquí usamos la de detección de anomalías: aprende
> el comportamiento normal de una serie temporal y marca los valores que se salen del intervalo
> esperado.

Al terminar, revisa el resultado:

```sql
SELECT series, ts, ROUND(y/1e6,1) AS mb_out, ROUND(forecast/1e6,1) AS mb_expected,
       ROUND(upper_bound/1e6,1) AS mb_upper, ROUND(y/forecast) AS x_sobre_previsto
FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES WHERE is_anomaly ORDER BY x_sobre_previsto DESC;
```

**Resultado esperado:** dos anomalías. La primera, muy destacada: la subred 10.20.8 el 17 de
octubre, con unos 5.374 MB de salida frente a unos 5,3 MB previstos (unas 1.000 veces más). La
segunda, menor (10.20.9 el 19 de octubre, 8,9 MB frente a un máximo de 8,2 MB), es un falso
positivo. El modelo prioriza; la decisión la sigue tomando el analista.

Para que el resto del laboratorio lea tus resultados, refresca la tabla de compatibilidad:

```sql
CREATE OR REPLACE TABLE SECURITY_LAKE.GOLD.NET_ANOMALIES COPY GRANTS AS
SELECT * FROM SECURITY_LAKE.GOLD.EGRESS_ANOMALIES;
```

**Si no tienes Cortex Code o algo falla:** los mismos objetos ya existen, porque los creó
`sql/backup/ml_modelos_respaldo.sql` en el paso 1.4. Ejecuta directamente la consulta anterior. Si
Cortex Code entrena sobre la vista y devuelve `input_data is empty`, es la row access policy
`RAP_BY_UNIT`, que filtra todo dentro del entrenamiento: pídele que entrene sobre la tabla
`EGRESS_DAILY_SUBNET`.

**Reto.** Pide a Cortex Code que repita la detección con `prediction_interval` 0,99 en lugar de
0,999. ¿Cuántas anomalías salen ahora y qué te dice eso sobre el umbral?

### 4.4 Operación: alertas y tareas programadas

```sql
SELECT detection, COUNT(*) AS alerts, MIN(event_time) AS first_ev,
       MAX(event_time) AS last_ev, COUNT_IF(triage IS NOT NULL) AS triaged
FROM SECURITY_LAKE.GOLD.ALERTS GROUP BY detection ORDER BY alerts DESC;

SHOW TASKS IN SCHEMA SECURITY_LAKE.GOLD;
```

> **Task.** Una *task* es una tarea programada de Snowflake que ejecuta SQL o un procedimiento
> según un horario (con sintaxis cron) o cuando llegan datos nuevos. Sustituye al cron o al
> orquestador externo.

**Resultado esperado:** diez alertas repartidas en cinco detecciones, todas ya priorizadas con IA.
La task `DETECTIONS_HOURLY` llama cada hora al procedimiento `RUN_DETECTIONS()`, que ejecuta las
detecciones y escribe las alertas nuevas. Está suspendida para no consumir créditos; se activaría
con `ALTER TASK SECURITY_LAKE.GOLD.DETECTIONS_HOURLY RESUME`. El script incluye también la alerta
`SOURCE_SILENT_ALERT`, que envía un correo cuando una fuente deja de enviar.

### 4.5 Probar un cambio de regla sobre un clon

El turno de noche se queja de ruido y propone subir el umbral del túnel DNS de 200 a 2.000
etiquetas distintas por día. Antes de tocar producción, clona el lake entero y prueba el cambio en
el clon. Ejecuta el bloque A1 de `sql/09_timetravel_clone.sql`:

```sql
USE ROLE SYSADMIN;
CREATE DATABASE SECURITY_LAKE_DEV CLONE SECURITY_LAKE;
GRANT OWNERSHIP ON DATABASE SECURITY_LAKE_DEV TO ROLE SOC_ADMIN COPY CURRENT GRANTS;
USE ROLE SOC_ADMIN;
SHOW DYNAMIC TABLES IN DATABASE SECURITY_LAKE_DEV;
SHOW TASKS IN DATABASE SECURITY_LAKE_DEV;
```

> **Zero-Copy Clone.** Un clon es una copia instantánea de una base de datos, un esquema o una
> tabla que no duplica los datos: comparte el almacenamiento con el original y solo se paga lo que
> cambie después.

**Resultado esperado:** el clon tarda unos 28 segundos. Las dynamic tables aparecen en estado
`SUSPENDED` y las tasks en `suspended`: el clon no ejecuta nada por su cuenta. Cuidado: las dynamic
tables y vistas usan nombres completos (`SECURITY_LAKE....`), así que si las reanudas leerían de
producción.

Sigue con el script: redefine `SECURITY_LAKE_DEV.GOLD.DET_DNS_TUNNEL` con el umbral de 2.000, borra
las alertas de túnel del clon, ejecuta `CALL RUN_DETECTIONS();` y compara con producción:

```sql
SELECT detection, COUNT_IF(env = 'PROD') AS prod, COUNT_IF(env = 'DEV') AS dev
FROM (SELECT 'PROD' AS env, detection FROM SECURITY_LAKE.GOLD.ALERTS
      UNION ALL SELECT 'DEV', detection FROM SECURITY_LAKE_DEV.GOLD.ALERTS)
GROUP BY 1 ORDER BY 1;
```

**Para pensar:** ¿qué detección cambia y qué incidente desaparece? ¿Promoverías el cambio?

### 4.6 Deshacer un error con Time Travel

A mitad de turno alguien lanza un `DELETE` sin el filtro correcto y vacía la cola de alertas
abiertas. Ejecuta el bloque A2 del script `09`, siempre sobre el clon:

```sql
USE SCHEMA SECURITY_LAKE_DEV.GOLD;
SELECT SYSTEM$WAIT(60);            -- solo si acabas de crear el clon
SET t_antes = CURRENT_TIMESTAMP();
DELETE FROM ALERTS WHERE status = 'NEW';
SET q_borrado = LAST_QUERY_ID();

SELECT (SELECT COUNT(*) FROM ALERTS) AS ahora,
       (SELECT COUNT(*) FROM ALERTS AT(OFFSET => -60)) AS hace_60_segundos,
       (SELECT COUNT(*) FROM ALERTS BEFORE(STATEMENT => $q_borrado)) AS justo_antes_del_delete,
       (SELECT COUNT(*) FROM ALERTS AT(TIMESTAMP => $t_antes)) AS en_t_antes;
```

> **Time Travel.** Snowflake conserva las versiones anteriores de los datos durante un periodo de
> retención (un día por defecto, hasta 90 en Enterprise), de modo que se puede consultar una tabla
> tal como estaba en un instante (`AT`), justo antes de una sentencia concreta (`BEFORE`) o
> recuperar una tabla borrada con `UNDROP`. Pasado ese periodo, las tablas permanentes tienen siete
> días de Fail-safe, recuperables solo por Soporte de Snowflake.

Continúa con el script: recupera las filas con `INSERT INTO ALERTS SELECT * FROM ALERTS
BEFORE(STATEMENT => $q_borrado) WHERE status = 'NEW'`, crea una copia de la tabla tal como estaba
con `CLONE ... BEFORE(STATEMENT => ...)`, bórrala con `DROP TABLE` y recupérala con `UNDROP TABLE`,
y revisa la retención de cada tabla en `INFORMATION_SCHEMA.TABLES`.

El script termina con un bloque comentado que crea un clon forense,
`SECURITY_LAKE_EVIDENCIA_20261017`, con `CLONE SECURITY_LAKE AT(TIMESTAMP => ...)`: congela el lake
tal como estaba antes de un incidente, para conservarlo como evidencia de solo lectura. Su creación
queda registrada en `QUERY_HISTORY` y `ACCESS_HISTORY`.

**Reto.** Escribe la consulta que responda a la pregunta del informe del incidente: "¿qué alertas
había en la cola en el instante `$t_antes`?".

**Reto.** ¿Por qué `AT(OFFSET => -3600)` puede fallar sobre el clon y `BEFORE(STATEMENT => ...)` no?

### 4.7 Hunting

Ejecuta el script `05` paso a paso. Primero etiqueta la sesión para poder medir tus consultas
después:

```sql
ALTER SESSION SET QUERY_TAG = 'workshop_hunting';
```

Busca un dominio en los logs originales de un año, sin normalizar:

```sql
SELECT raw:ts::TIMESTAMP_NTZ AS ts, raw:client_ip::STRING AS host, raw:query::STRING AS query, src_file
FROM SECURITY_LAKE.BRONZE.DNS_RAW
WHERE SEARCH(raw, 'update-check-srv.com')
ORDER BY ts;
```

Busca todo lo que tocó un host en doce meses, sobre la vista común `ALL_EVENTS`, que une todas las
fuentes:

```sql
SELECT class, COUNT(*) AS events, MIN(event_time) AS first_seen, MAX(event_time) AS last_seen
FROM SECURITY_LAKE.SILVER.ALL_EVENTS
WHERE (src_ip = '10.20.8.15' OR dst_ip = '10.20.8.15')
  AND event_time >= DATEADD('month', -12, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY class;
```

Calcula los principales destinos por volumen del año, anota el tiempo, cambia el warehouse a LARGE,
repite la consulta y vuelve a XSMALL:

```sql
SELECT dst_ip, COUNT(DISTINCT src_ip) AS hosts, SUM(bytes_out) AS bytes_out
FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY
WHERE source = 'netflow' AND event_time >= DATEADD('year', -1, '2026-10-21'::TIMESTAMP_NTZ)
GROUP BY dst_ip ORDER BY bytes_out DESC LIMIT 20;

USE ROLE SOC_ADMIN;
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'LARGE';
-- (repetir la consulta anterior)
ALTER WAREHOUSE SOC_WH SET WAREHOUSE_SIZE = 'XSMALL';
```

Activa Search Optimization sobre los logs DNS originales, repite la búsqueda del dominio y compara
en el Query Profile las particiones leídas:

```sql
ALTER TABLE SECURITY_LAKE.BRONZE.DNS_RAW ADD SEARCH OPTIMIZATION ON FULL_TEXT(raw), EQUALITY(raw:client_ip);
SHOW TABLES LIKE 'DNS_RAW' IN SCHEMA SECURITY_LAKE.BRONZE;
```

> **Search Optimization y Query Profile.** *Search Optimization* es un servicio que crea
> estructuras de búsqueda sobre una tabla para que las búsquedas puntuales (una IP, un dominio, un
> texto) no tengan que recorrerla entera. La columna `search_optimization_progress` llega a 100
> cuando terminan de construirse. El *Query Profile* es el plan de ejecución visual de una
> consulta, donde se ve cuánto ha leído y dónde ha gastado el tiempo. Lo abres desde el historial
> de consultas.

Por último, exporta un resultado al stage para compartirlo con otro equipo y revisa lo que han
costado tus consultas:

```sql
COPY INTO @SECURITY_LAKE.BRONZE.S3_LOGS/exports/ioc_hits_
  FROM (SELECT * FROM SECURITY_LAKE.GOLD.DET_IOC_HITS)
  FILE_FORMAT = (TYPE = CSV COMPRESSION = GZIP) HEADER = TRUE OVERWRITE = TRUE;
LIST @SECURITY_LAKE.BRONZE.S3_LOGS/exports/;
```

El script termina consultando `QUERY_HISTORY` filtrado por la etiqueta `workshop_hunting`, con los
segundos y los bytes de cada consulta. Ten en cuenta que el conjunto es pequeño: las consultas
tardan entre 0,2 y 2 segundos y no son una medida de rendimiento a escala.

**Reto.** Escribe una detección nueva como vista en GOLD, por ejemplo, conexiones denegadas al
puerto 22 por IP de origen y hora a partir de `BRONZE.FW_RAW` (el script `05` tiene un punto de
partida con `ILIKE '%action=deny%'`).

**Reto.** Busca en `ALL_EVENTS` todo lo relacionado con otro de los indicadores de la tabla
`BRONZE.IOC`. ¿Aparece en más de una fuente?

---

## Módulo 5 · Fraude SIM swap con ML

**Objetivo:** construir con Cortex Code un modelo de clasificación para priorizar solicitudes de
cambio de SIM sospechosas (`prompts/ml_fraude_sim.md`, con `sql/06_sim_swap_ml.sql` como
consultas de referencia).

El SIM swap consiste en conseguir que el operador traslade el número de la víctima a una SIM del
atacante, lo que le permite recibir los códigos de un solo uso del banco. Las solicitudes
anteriores al 18 de octubre llevan una etiqueta `is_fraud`, que sirve para entrenar el modelo; las
posteriores llegan sin etiqueta, y son las que el modelo tiene que puntuar.

> **Clasificación con ML Functions.** Igual que la detección de anomalías, la función de
> clasificación se entrena con una consulta SQL que le indica qué columna hay que predecir (aquí,
> `is_fraud`) y después puntúa las filas nuevas con una probabilidad. `SHOW_FEATURE_IMPORTANCE`
> indica qué variables pesan más en la decisión.

En Cortex Code, con `SOC_ADMIN` y `SOC_WH`, pega uno a uno los prompts de
`prompts/ml_fraude_sim.md` y ejecuta después la consulta de comprobación de cada paso:

| Prompt | Qué pide | Resultado esperado |
|---|---|---|
| 1 | Describir `BRONZE.SIM_REQUESTS` | 58.650 filas etiquetadas (1.187 fraudes, un 2 %) y 675 sin etiquetar, del 18 al 21 de octubre |
| 2 | Vista `GOLD.SIM_TRAIN`, sin `msisdn`, tienda ni agente como variables | 58.650 filas, 2,02 % de fraude |
| 3 | Entrenar `GOLD.SIM_FRAUD_MODEL`, con métricas e importancia de variables | unos 15 s; `ACCOUNT_AGE_DAYS` y `REQUESTS_24H` en cabeza |
| 4 | Puntuar las solicitudes nuevas en `GOLD.SIM_SCORED` | 675 filas, 86 con `fraud_score > 0.5` |
| 5 | Cola de investigación y concentración por tienda y agente | un grupo destaca |

`SIM_SCORED` es una tabla nueva y pierde la etiqueta PII y la máscara de `msisdn`. Tras el prompt
4, pide a Cortex Code que ejecute el bloque final de `sql/backup/ml_modelos_respaldo.sql` para
reaplicarlas; lo comprobarás en el módulo 7.

**Si no tienes Cortex Code o algo falla:** el modelo y `SIM_SCORED` ya existen por el respaldo del
paso 1.4; ejecuta directamente las consultas de `sql/06_sim_swap_ml.sql`.

```sql
SELECT request_ts, msisdn, request_type, store_id, agent_id, ROUND(fraud_score,3) AS score
FROM SECURITY_LAKE.GOLD.SIM_SCORED WHERE fraud_score > 0.5
ORDER BY fraud_score DESC LIMIT 25;
```

**Para pensar:** ¿se repiten la tienda o el agente en la cola? ¿Qué sugeriría eso? El script
incluye una consulta de concentración que lo cuantifica.

Las métricas del modelo saldrán perfectas porque los datos son sintéticos y el patrón es muy fácil
de separar. Con datos reales, el umbral se ajusta comparando el coste de bloquear a un cliente
legítimo con el de dejar pasar un fraude.

**Reto.** Cambia el umbral de `0.5` a `0.2` y compara cuántas solicitudes entran en la cola.

**Reto.** El prompt 2 excluye a propósito la tienda y el agente. ¿Por qué, si precisamente el
anillo está en una tienda y un agente concretos?

---

## Módulo 6 · IA para el SOC: triage, runbooks, agente, MCP y dashboard

**Objetivo:** priorizar alertas con un modelo de lenguaje, consultar runbooks en lenguaje natural
y hablar con un agente que respeta los permisos (script `sql/07_ai_triage.sql`).

> **Cortex.** Es el nombre del conjunto de servicios de IA de Snowflake. Incluye funciones SQL que
> llaman a modelos de lenguaje, un buscador semántico sobre documentos y agentes. Los modelos se
> ejecutan dentro del perímetro de Snowflake, así que los datos no salen hacia un proveedor
> externo.

### 6.1 Triage

```sql
SELECT detection, entity, unit, LEFT(triage::STRING, 300) AS triage_ia
FROM SECURITY_LAKE.GOLD.ALERTS WHERE triage IS NOT NULL LIMIT 10;
```

Cada alerta lleva un JSON con un resumen, una severidad, la táctica de MITRE ATT&CK y los
siguientes pasos recomendados. La función `AI_COMPLETE`, cuando se le pasa un esquema JSON,
devuelve datos estructurados que se pueden consultar con SQL, por ejemplo con
`WHERE triage:severidad = 'critica'`.

### 6.2 Runbooks

El script crea el servicio `RUNBOOK_SEARCH` sobre los runbooks de `runbooks/`. Pregúntale, por
ejemplo, "¿Cómo gestionamos el último caso de túnel DNS?". Devuelve el fragmento del runbook
correspondiente aunque la pregunta no use las mismas palabras.

> **Cortex Search.** Es un servicio de búsqueda que combina búsqueda semántica (por significado) y
> por palabras clave sobre texto, en este caso los runbooks del SOC. Es la pieza de recuperación
> que usa el agente para basar sus respuestas en documentación propia.

### 6.3 Agente

En AI & ML > Snowflake Intelligence, abre el agente `SOC_AGENT` y pregúntale: "¿Qué alertas de
severidad crítica hay y qué entidad afectan?". El agente responde y enseña la SQL que ha generado.
Después pregunta qué runbook aplicar a esa alerta: para responder combina la consulta de datos con
la búsqueda en los runbooks. Cada pregunta tarda entre 20 y 40 segundos.

> **Snowflake Intelligence y agentes.** Un *Cortex Agent* es un asistente que recibe preguntas en
> lenguaje natural y decide qué herramienta usar: puede generar SQL sobre las tablas a partir de
> un modelo semántico que describe los datos, buscar en documentos con Cortex Search o combinar
> ambas cosas. *Snowflake Intelligence* es la interfaz de chat donde los usuarios hablan con esos
> agentes.

### 6.4 MCP

El script crea el servidor `SOC_MCP`, que expone el agente a clientes externos (asistentes como
Claude o Cursor, u otros agentes) con autenticación OAuth y respetando los roles.

> **MCP (Model Context Protocol).** Es un protocolo abierto para que las aplicaciones de IA usen
> herramientas y datos externos. Snowflake puede publicar un servidor MCP gestionado, de modo que
> un asistente externo consulte los datos con los mismos permisos que tendría el usuario.

### 6.5 Dashboard

Despliega el dashboard de `streamlit/soc_dashboard.py`. Desde Snowsight puedes subir el fichero al
stage con la interfaz (Catalog > stage > "+ Files") o, con Snowflake CLI o SnowSQL, con `PUT`:

```sql
USE ROLE SOC_ADMIN;
CREATE STAGE IF NOT EXISTS SECURITY_LAKE.GOLD.APP_STAGE;
PUT file://streamlit/soc_dashboard.py @SECURITY_LAKE.GOLD.APP_STAGE/soc/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE;
CREATE OR REPLACE STREAMLIT SECURITY_LAKE.GOLD.SOC_DASHBOARD
  FROM '@SECURITY_LAKE.GOLD.APP_STAGE/soc/' MAIN_FILE = 'soc_dashboard.py'
  QUERY_WAREHOUSE = SOC_WH RUNTIME_NAME = 'SYSTEM$WAREHOUSE_RUNTIME'
  TITLE = 'SOC · Security Data Lake';
GRANT USAGE ON STREAMLIT SECURITY_LAKE.GOLD.SOC_DASHBOARD TO ROLE SOC_ANALYST;
```

Ábrelo en Projects > Streamlit > `SOC · Security Data Lake`. Muestra las alertas por detección,
los eventos por fuente y la cola de SIM swap. El primer arranque tarda entre 30 y 60 segundos.

> **Streamlit en Snowflake.** Streamlit es un framework de Python para crear aplicaciones web de
> datos. Snowflake puede alojar y ejecutar estas aplicaciones dentro de la cuenta, de modo que el
> dashboard no necesita servidor propio y lee los datos con los permisos del usuario.

**Reto.** Llama tú mismo a `AI_COMPLETE` con una de las filas de `GOLD.DET_O365_MASS_DOWNLOAD` y
pide un resumen de dos frases para un responsable no técnico.

**Reto.** Haz al agente una pregunta que obligue a cruzar dos fuentes, por ejemplo, qué hizo en
Office 365 la usuaria con más descargas en la semana del incidente.

---

## Módulo 7 · Gobierno y auditoría

**Objetivo:** comprobar que el mismo dato se ve distinto según el rol, en cualquier consulta,
dashboard o agente, y que todo acceso queda registrado (script `sql/08_governance.sql`).

### 7.1 Usuario de prueba

Para ver las políticas como las vería un analista, crea un usuario sin roles secundarios:

```sql
USE ROLE USERADMIN;
CREATE USER IF NOT EXISTS SOC_DEMO_ANALYST PASSWORD = '<generar>' MUST_CHANGE_PASSWORD = FALSE
  DEFAULT_ROLE = SOC_ANALYST DEFAULT_WAREHOUSE = SOC_WH DEFAULT_SECONDARY_ROLES = ();
GRANT ROLE SOC_ANALYST TO USER SOC_DEMO_ANALYST;
```

Inicia sesión con él en una ventana de incógnito. Como alternativa, en tu propia sesión puedes usar
`USE ROLE SOC_ANALYST; USE SECONDARY ROLES NONE;`. Sin esto, tus roles secundarios te darían los
permisos de `THREAT_HUNTER` y lo verías todo.

### 7.2 Enmascaramiento con hash determinista

```sql
USE ROLE SOC_ANALYST;
USE SECONDARY ROLES NONE;
SELECT event_time, user_name, src_ip, activity, unit
FROM SECURITY_LAKE.SILVER.AUTH_ACTIVITY LIMIT 10;
```

**Resultado esperado:** `user_name` aparece como `h_…`. Como el mismo usuario produce siempre el
mismo hash, el analista puede correlacionar eventos sin ver el dato.

> **Masking policy y tags.** Una *política de enmascaramiento* es una función que Snowflake aplica
> a una columna en el momento de la consulta y que decide, según el rol de quien pregunta, si
> devuelve el valor real o una versión enmascarada. Un *tag* es una etiqueta que se pone a una
> columna u objeto (por ejemplo, `DATA_SENSITIVITY = 'PII'`) y a la que se pueden asociar
> políticas para aplicarlas de forma masiva.

### 7.3 Proteger un dato nuevo con Cortex Code

El equipo de fraude quiere publicar a los analistas la cola de SIM de alto riesgo, pero el
identificador del agente comercial es un dato personal de un empleado. Vuelve a `SOC_ADMIN`
(`USE ROLE SOC_ADMIN; USE SECONDARY ROLES ALL;`) y pega en Cortex Code los cuatro prompts de
`prompts/enmascaramiento.md`, ejecutando la consulta de comprobación de cada paso:

| Prompt | Qué pide | Resultado esperado |
|---|---|---|
| 1 | Inventario de políticas y etiquetas | `MASK_PII_HASH` en `AUTH_ACTIVITY.user_name`, `SIM_REQUESTS.msisdn` y `SIM_SCORED.msisdn`; `agent_id` sin proteger |
| 2 | Vista `GOLD.V_SIM_RIESGO_AGENTES` con `SELECT` para `SOC_ANALYST` | 86 filas |
| 3 | Política `GOVERNANCE.MASK_AGENT_ID` sobre `agent_id`, etiquetada como PII | aplicada a la vista |
| 4 | Verificar con `SOC_ANALYST` (sin roles secundarios) y con `THREAT_HUNTER` | ver tabla siguiente |

| Rol | store_id | agent_id | msisdn |
|---|---|---|---|
| SOC_ANALYST | S-0457 | `A-****` | `h_515a806e…` (hash) |
| THREAT_HUNTER | S-0457 | `A-1123` | en claro |

**Para pensar:** no has aplicado ninguna política a `msisdn` en la vista y aun así sale
enmascarado. ¿Por qué?

Las políticas de referencia de este módulo están en `sql/08_governance.sql`; si no tienes Cortex
Code, puedes escribir la vista y la política a mano tomándolo como modelo.

### 7.4 Segregación por unidad de negocio

```sql
USE ROLE SOC_ANALYST;
USE SECONDARY ROLES NONE;
SELECT unit, COUNT(*) AS events FROM SECURITY_LAKE.SILVER.NETWORK_ACTIVITY GROUP BY unit;
```

**Resultado esperado:** como `SOC_ANALYST` solo aparece la unidad UES, con 737.464 eventos. Repite
la consulta con `THREAT_HUNTER`: aparecen UES, UDE y UBR.

> **Row access policy.** Es una política que filtra las filas que puede ver cada rol. Se escribe
> una vez sobre la tabla y se aplica a cualquier consulta, informe o agente que la lea.

Haz una pregunta al agente desde la sesión de `SOC_DEMO_ANALYST`: la respuesta también sale
enmascarada y filtrada, porque el agente consulta con el rol del usuario.

### 7.5 Auditoría

```sql
USE ROLE ACCOUNTADMIN;
SELECT query_start_time, user_name, f.value:"objectName"::STRING AS object,
       f.value:"columns" AS columns
FROM SNOWFLAKE.ACCOUNT_USAGE.ACCESS_HISTORY, LATERAL FLATTEN(base_objects_accessed) f
WHERE f.value:"objectName"::STRING ILIKE 'SECURITY_LAKE.SILVER.AUTH%'
ORDER BY 1 DESC LIMIT 15;
```

> **ACCOUNT_USAGE y ACCESS_HISTORY.** `SNOWFLAKE.ACCOUNT_USAGE` es un esquema de solo lectura que
> Snowflake mantiene en cada cuenta con el histórico de consultas, accesos, inicios de sesión y
> consumo. `ACCESS_HISTORY` registra qué usuario leyó o escribió qué tablas y columnas en cada
> consulta.

Esta vista tiene una latencia de hasta tres horas: tus lecturas de los pasos anteriores
aparecerán más tarde.

### 7.6 Control de coste

```sql
USE ROLE ACCOUNTADMIN;
SHOW RESOURCE MONITORS;
```

`SOC_MONITOR` está asignado a `SOC_WH`, avisa al llegar al 80 % de los 50 créditos y suspende el
warehouse al 100 %.

> **Resource monitor.** Es un límite de consumo de créditos que se asigna a uno o varios
> warehouses y que puede avisar o suspenderlos al alcanzar un umbral.

Al terminar el módulo, vuelve a tu rol habitual con `USE ROLE SOC_ADMIN; USE SECONDARY ROLES ALL;`.

**Reto.** Revisa en `sql/08_governance.sql` la política `MASK_PII_HASH` y a qué columnas se
aplica. Fíjate en que se aplica dos veces a `msisdn`: en `BRONZE.SIM_REQUESTS` y en
`GOLD.SIM_SCORED`. `SIM_SCORED` se creó con `CREATE TABLE AS` en el módulo 5 (o en el respaldo), y una copia así
no hereda el enmascaramiento de la tabla de origen. Comprueba con `SOC_ANALYST` que `msisdn` sale
como hash en `SIM_SCORED` y que aun así puedes agrupar por él. ¿Cómo evitarías tener que acordarte
de cada copia? Pista: asociando la política al tag `DATA_SENSITIVITY`, para que se aplique a
cualquier columna etiquetada como PII.

---

## Lectura opcional · Coexistencia con Splunk

Si tu SOC usa Splunk, este data lake no lo sustituye: se pone a su lado. Estas son las opciones
de integración, aunque no forman parte del laboratorio.

**Splunk consulta Snowflake sin ingerir.** Splunk Cloud Platform ofrece Federated Search for
Snowflake, que permite consultar tablas y vistas de Snowflake con SPL2 sin ingerir esos datos y
correlacionarlos con los que ya están en Splunk. Es una función de Splunk y requiere Splunk Cloud
Platform alojado en AWS.

**De Splunk a Snowflake no hay federación nativa:** los datos se copian a Snowflake. Hay cuatro
caminos. El primero es Openflow con el procesador
[`GetSplunk`](https://docs.snowflake.com/en/user-guide/data-integration/openflow/processors/getsplunk),
que lanza búsquedas contra la API de Splunk y, con la estrategia de rango temporal gestionada,
recuerda la última ejecución para traer solo lo nuevo. El segundo es streaming con Kafka (conector
Splunk Source de Confluent y conector de Snowflake). El tercero son lotes: búsquedas con la API
REST de Splunk exportadas a S3 y cargadas con Snowpipe o consultadas con tablas externas, igual que
en este laboratorio. El cuarto, una función externa que llame a la API de Splunk, es una
integración a medida y no una federación real.

> **Funciones externas.** Una *external function* es una función SQL de Snowflake que, al
> ejecutarse, llama a un servicio HTTP externo (a través de un API gateway) y devuelve su
> respuesta como resultado de la consulta.

**De Snowflake a Splunk.** Con Openflow, `PutSplunkHTTP` envía eventos al HTTP Event Collector y
`QuerySplunkIndexingStatus` confirma que se han indexado. Así se pueden reenviar a Splunk las
alertas de `GOLD.ALERTS`.

> **Openflow.** Es el servicio de integración de datos de Snowflake, basado en Apache NiFi.
> Permite montar flujos visuales que mueven datos entre sistemas (SIEM, Kafka, bases de datos,
> APIs) y Snowflake, y se puede desplegar gestionado por Snowflake o en tu propia nube (BYOC).

**Arquitectura recomendada.** Los datos recientes y prioritarios para la detección rápida se
quedan en Splunk. El histórico completo va a Snowflake para la retención, el hunting, la analítica
y el ML. Cuando hace falta histórico, Splunk federa la consulta hacia Snowflake, y las alertas de
alto valor de Snowflake vuelven a Splunk con Openflow.

---

## Problemas frecuentes

| Síntoma | Causa y solución |
|---|---|
| `LIST @S3_LOGS` falla o no devuelve nada (opción A) | La política de confianza del rol IAM no tiene los valores de `DESC INTEGRATION S3_SIEM_INT`, o el bucket de `STORAGE_ALLOWED_LOCATIONS` y la `URL` del stage no coinciden con el tuyo. Revisa el paso 1.3. Si no puedes resolverlo, usa la opción B; los scripts `02` a `08` no cambian. |
| Las comprobaciones de calidad aparecen como `SUSPENDED_INSUFFICIENT_PRIVILEGE` | Falta `EXECUTE DATA METRIC FUNCTION` en `SOC_ADMIN` (lo concede el script `00`). Si las comprobaciones se crearon antes del permiso, quítalas de la tabla y vuelve a añadirlas. |
| Data quality muestra "No checks" | La dynamic table no se ha refrescado desde que se asociaron: `ALTER DYNAMIC TABLE SECURITY_LAKE.SILVER.NETWORK_ACTIVITY REFRESH;`. |
| `AI_COMPLETE` falla por modelo no disponible | El modelo no está en tu región. Activa la inferencia entre regiones o cambia el modelo en `sql/07_ai_triage.sql`. |
| El dashboard falla con "pyproject.toml file does not exist" | Se creó en el runtime de contenedor. Créalo en el runtime de warehouse con el `CREATE OR REPLACE STREAMLIT ... RUNTIME_NAME = 'SYSTEM$WAREHOUSE_RUNTIME'` del módulo 6. |
| El dashboard no refleja los cambios en el código | La aplicación ejecuta una copia versionada de sus ficheros. Después de subir el fichero, vuelve a ejecutar `CREATE OR REPLACE STREAMLIT ... FROM '@SECURITY_LAKE.GOLD.APP_STAGE/soc/'`. |
| Error con el parámetro `hide_index` de `st.dataframe` | El runtime de warehouse no lo admite; quítalo del código. |
| El dashboard tarda en abrir | El primer arranque tarda entre 30 y 60 segundos. |
| El enmascaramiento o el filtrado de filas no se aplican | Tienes roles secundarios activos. Usa `USE SECONDARY ROLES NONE` o el usuario `SOC_DEMO_ANALYST`. |
| `ACCESS_HISTORY` o el consumo de Cortex aparecen vacíos | Las vistas de `ACCOUNT_USAGE` tienen entre una y tres horas de latencia. |
| La política de ciclo de vida no ha hecho nada | Tarda unas 24 horas en ejecutarse por primera vez. |
| Cortex Code devuelve `input_data is empty` al entrenar el modelo de anomalías | Está entrenando sobre una vista que lee `NETWORK_ACTIVITY`, filtrada por la row access policy. Pídele que entrene sobre la tabla `GOLD.EGRESS_DAILY_SUBNET`. |
| `msisdn` sale en claro en `SIM_SCORED` tras el módulo 5 | Al recrear la tabla se pierde la máscara. Ejecuta el bloque final de `sql/backup/ml_modelos_respaldo.sql`. |
| `AT(OFFSET => ...)` da el error 000707 en el clon | El desplazamiento cae antes de la creación del clon. Espera con `SYSTEM$WAIT(60)` o usa `BEFORE(STATEMENT => ...)`. |
| `CREATE DATABASE ... CLONE` falla con `SOC_ADMIN` | `SOC_ADMIN` no tiene `CREATE DATABASE`. Clona con `SYSADMIN` y cede la propiedad, como hace el script `09`. |
| `CREATE SHARE` falla por permisos | Requiere `ACCOUNTADMIN` o el privilegio `CREATE SHARE`. |

---

## Limpieza

Cuando termines, suspende lo que consume y borra el usuario de prueba, el clon, el share y los
objetos creados con Cortex Code en el módulo 7:

```sql
USE ROLE ACCOUNTADMIN;
DROP USER IF EXISTS SOC_DEMO_ANALYST;
DROP SHARE IF EXISTS SOC_IOC_SHARE;
DROP DATABASE IF EXISTS SECURITY_LAKE_DEV;
-- y cualquier SECURITY_LAKE_EVIDENCIA_* que hayas creado
DROP VIEW IF EXISTS SECURITY_LAKE.GOLD.V_SIM_RIESGO_AGENTES;
DROP MASKING POLICY IF EXISTS SECURITY_LAKE.GOVERNANCE.MASK_AGENT_ID;
ALTER TASK SECURITY_LAKE.GOLD.DETECTIONS_HOURLY SUSPEND;
ALTER WAREHOUSE SOC_WH SUSPEND;
```

Para desmontarlo todo, ejecuta `sql/99_teardown.sql`. Borra la base de datos `SECURITY_LAKE`, el
clon `SECURITY_LAKE_DEV`, el share `SOC_IOC_SHARE` y los
roles, el warehouse y el resource monitor creados en el script `00`. Si usaste la opción A, borra
también la integración (`DROP INTEGRATION S3_SIEM_INT;`), y en AWS elimina el bucket, el rol IAM y
su política, y rota las credenciales que usaste para subir los datos.

Para ver lo que ha costado el laboratorio, consulta
`SNOWFLAKE.ACCOUNT_USAGE.WAREHOUSE_METERING_HISTORY`.

---

## Solucionario: incidentes sembrados

No sigas leyendo si todavía quieres encontrarlos por tu cuenta. El generador inserta siete
incidentes; los de octubre generan las diez alertas de `GOLD.ALERTS`.

| Incidente | Fecha | Entidades | Dónde aparece |
|---|---|---|---|
| IOC histórico | 10-feb-2026 | 10.20.3.40 → update-check-srv.com | Módulo 4 (IOC y búsqueda en raw) |
| Fuerza bruta y privilegios | 14-oct | svc_backup / 185.220.101.45 | Módulo 4 (`MATCH_RECOGNIZE`) |
| Túnel DNS | 15 y 16-oct | 10.20.5.77 → x1f9-cdn.net | Módulo 2 (tamaño de fichero y consulta en sitio), módulo 4 y clon (4.5) |
| Descarga masiva en O365 | 16-oct | maria.lopez / 91.240.118.172 | Módulo 4 |
| Exfiltración de 5 GB | 17-oct | 10.20.8.15 → 45.137.21.9 | Módulo 4 (regla y ML) y módulo 6 (agente) |
| Anillo de SIM swap | 18 a 20-oct | tienda S-0457 / agente A-1123 | Módulo 5 |
| Fuente silenciosa | desde el 20-oct a las 12:00 | fw-bcn-02 | Módulo 4 (salud de fuentes) |

El **IOC histórico** es un host interno que, en febrero, hizo cuarenta consultas de madrugada a un
dominio que hoy figura en la lista de amenazas. Con un año de datos consultables, un indicador
nuevo se busca hacia atrás en segundos.

La **fuerza bruta** son sesenta inicios de sesión fallidos de la cuenta de servicio `svc_backup`
en unos cinco minutos, seguidos de un acceso correcto y de un evento 4672, que indica que la
sesión recibió privilegios especiales.

El **túnel DNS** son 1.500 consultas diarias, durante dos días, con subdominios largos y
aleatorios (unos 52 caracteres) hacia `x1f9-cdn.net`. Por eso los ficheros DNS de esos días pesan
unos 85 KB frente a los 23 KB habituales.

La **descarga masiva en Office 365** son quinientas descargas de SharePoint de la usuaria
`maria.lopez` en una sola hora y desde una IP inusual.

La **exfiltración de 5 GB** son cincuenta flujos de unos 100 MB entre las 3:00 y las 3:50 de la
madrugada, desde 10.20.8.15 hacia una IP externa, con una alerta de Suricata. `DET_EXFIL` la ve
como unas 43.000 veces la media del host, y el modelo de anomalías como 5.374 MB de salida de la
subred 10.20.8 frente a unos 5,3 MB previstos.

El **anillo de SIM swap** son veinticinco solicitudes diarias de cambio de SIM, durante tres días,
en la misma tienda y por el mismo agente, con dispositivo y ubicación nuevos: 75 solicitudes de
alto riesgo que apuntan a un posible fraude interno.

La **fuente silenciosa** es el firewall `fw-bcn-02`, que deja de enviar logs el 20 de octubre a
mediodía.

### Respuestas a los retos de cómputo, ingesta, compartición, ML, clon y Time Travel

**Módulo 1 · `HUNT_WH`.** `CREATE WAREHOUSE HUNT_WH WAREHOUSE_SIZE = 'LARGE' AUTO_SUSPEND = 60
INITIALLY_SUSPENDED = TRUE;`. Una búsqueda de 5 segundos sobre el warehouse parado factura 60
segundos, porque cada arranque tiene un mínimo de un minuto; las consultas siguientes mientras siga
encendido se facturan por segundo.

**Módulo 2 · Verificación de carga.** Con los datos del laboratorio, el bloque de verificación no
debe mostrar ficheros pendientes ni con errores en ninguna fuente. El segundo `COPY` de `DNS_RAW`
carga 0 filas: los metadatos de carga (64 días) recuerdan los ficheros ya cargados, y por eso nunca
se usa `FORCE = TRUE`.

**Módulo 2 · Mecanismo por fuente.** Auditoría diaria de Office 365 en S3: `COPY` programado con una
task. Logs de proxy cada cinco minutos en S3: Snowpipe con auto-ingest. Alertas de EDR en Kafka:
Snowpipe Streaming con el conector de Kafka.

**Módulo 3 · Vista compartida.** Agrega por indicador para no exponer hosts internos ni usuarios a
otra organización: el CSIRT necesita saber qué indicador se ha visto, cuántas veces y cuándo, no qué
máquina concreta. Para limitarla a UES, se añade `WHERE unit = 'UES'` a la vista (o una row access
policy que tenga en cuenta la cuenta consumidora, por ejemplo con `CURRENT_ACCOUNT()`).

**Módulo 4 · `prediction_interval`.** Con 0,99 la banda esperada es más estrecha y salen más
anomalías leves; la de 10.20.8 el 17 de octubre sigue siendo, con diferencia, la primera. El umbral
es un compromiso entre falsos positivos y casos perdidos, y lo decide el SOC.

**Módulo 4 · Clon.** Cambia `dns_tunnel`: con el umbral de 2.000 desaparecen las dos alertas reales
del túnel de 10.20.5.77 de los días 15 y 16 de octubre, que tienen unas 1.500 etiquetas distintas
por día. El cambio no se promueve: subir el umbral habría escondido el incidente real. Producción no
se ha tocado.

**Módulo 4 · Cola en `$t_antes`.**

```sql
SELECT detection, entity, event_time, status
FROM SECURITY_LAKE_DEV.GOLD.ALERTS AT(TIMESTAMP => $t_antes)
ORDER BY event_time;
```

**Módulo 4 · `OFFSET` frente a `STATEMENT`.** `AT(OFFSET => -3600)` pide la tabla tal como estaba
hace una hora, y el clon no existía entonces: Time Travel no puede ir más atrás de la creación del
objeto (error 000707). `BEFORE(STATEMENT => ...)` apunta al instante exacto anterior al `DELETE`,
que es posterior a la creación del clon. Además, `OFFSET` es aproximado y puede incluir otros
cambios; `STATEMENT` es exacto.

**Módulo 5 · Variables del modelo.** Si la tienda y el agente fueran variables, el modelo aprendería
qué tiendas o agentes tuvieron fraude en el pasado, y no reconocería un anillo en una tienda nueva.
Con variables de comportamiento (antigüedad de la cuenta, solicitudes en 24 horas, tipo, hora), el
modelo puntúa cada solicitud por sí misma, y la concentración en S-0457 / A-1123 aparece después al
agrupar: es una evidencia independiente del modelo.

**Módulo 7 · `msisdn` en la vista.** La política `MASK_PII_HASH` está aplicada a la columna de la
tabla base `GOLD.SIM_SCORED`, y las políticas de una tabla se aplican también a cualquier vista que
la lea. Por eso `POLICY_REFERENCES` sobre la vista solo muestra `MASK_AGENT_ID`.
