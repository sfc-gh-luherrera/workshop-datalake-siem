"""Sube la salida local del generador a un stage interno (ensayo sin AWS).

Uso: python upload_internal.py --dir ./out --connection <nombre en connections.toml>
     python upload_internal.py --dir ./out --resume --workers 4   # reanuda una subida cortada
Mantiene el layout <source>/YYYY/MM/DD/ dentro de @SECURITY_LAKE.BRONZE.S3_LOGS.

Resiliencia:
  - timeouts de login/red en la conexión (nunca se queda colgado),
  - un PUT por <source>/YYYY/MM (lotes mensuales pequeños y re-ejecutables),
  - OVERWRITE=FALSE: re-ejecutar no vuelve a subir lo que ya está,
  - --resume: compara tamaños con LIST del stage y omite ficheros ya subidos,
  - reintentos con backoff exponencial por lote, resumen de fallos y exit code != 0.
"""
import argparse
import random
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import snowflake.connector

MAX_RETRIES = 5
STAGE = "S3_LOGS"

p = argparse.ArgumentParser()
p.add_argument("--dir", required=True)
p.add_argument("--connection", default=None)
p.add_argument("--workers", type=int, default=8, help="lotes mensuales en paralelo (una conexión por hilo)")
p.add_argument("--resume", action="store_true", help="omite ficheros que ya están en el stage con el mismo tamaño")
p.add_argument("--progress-every", type=int, default=10, help="línea de progreso cada N lotes")
p.add_argument("--parallel", type=int, default=8, help="PARALLEL del PUT")
a = p.parse_args()
if a.workers < 1 or a.progress_every < 1:
    p.error("--workers y --progress-every deben ser >= 1")


def connect():
    kw = dict(login_timeout=60, network_timeout=300, socket_timeout=300)
    con = snowflake.connector.connect(connection_name=a.connection, **kw) if a.connection \
        else snowflake.connector.connect(**kw)
    cur = con.cursor()
    cur.execute("USE ROLE SOC_ADMIN")
    cur.execute("USE SCHEMA SECURITY_LAKE.BRONZE")
    return con


root = Path(a.dir).resolve()
files = [f for f in root.rglob("*") if f.is_file() and not f.name.endswith(".part")]

# Ficheros ya presentes en el stage: ruta relativa -> tamaño
remote = {}
if a.resume:
    con = connect()
    for row in con.cursor().execute(f"LIST @{STAGE}"):
        # name viene como "s3_logs/dns/2026/10/01/dns_20261001.json.gz"
        remote[row[0].split("/", 1)[1] if "/" in row[0] else row[0]] = int(row[1])
    con.close()
    print(f"--resume: {len(remote)} ficheros ya en @{STAGE}", flush=True)

# Lotes por <source>/YYYY/MM (o el directorio padre si no sigue el layout, p.ej. ioc/, runbooks/)
batches = defaultdict(list)
skipped = 0
for f in files:
    rel = f.relative_to(root).as_posix()
    if a.resume and remote.get(rel) == f.stat().st_size:
        skipped += 1
        continue
    m = re.match(r"^([^/]+/\d{4}/\d{2})/", rel)
    batches[m.group(1) if m else f.parent.relative_to(root).as_posix()].append(f)

local = threading.local()


def cursor():
    if not hasattr(local, "con"):
        local.con = connect()
    return local.con.cursor()


def upload_batch(key, batch):
    # Agrupa por día: el PUT conserva el layout <source>/YYYY/MM/DD/
    by_dir = defaultdict(list)
    for f in batch:
        by_dir[f.parent].append(f)
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            for d, fs in sorted(by_dir.items()):
                rel = d.relative_to(root).as_posix()
                pattern = f"{d}/*" if not a.resume else None
                srcs = [pattern] if pattern else [str(f) for f in fs]
                for src in srcs:
                    cursor().execute(f"PUT 'file://{src}' @{STAGE}/{rel}/ "
                                     f"AUTO_COMPRESS=FALSE OVERWRITE=FALSE PARALLEL={a.parallel}")
            return len(batch)
        except Exception as e:  # noqa: BLE001
            if hasattr(local, "con"):  # conexión posiblemente rota: se recrea
                try:
                    local.con.close()
                except Exception:  # noqa: BLE001
                    pass
                del local.con
            if attempt == MAX_RETRIES:
                raise
            wait = min(60, 2 ** attempt) + random.random()
            print(f"Reintento {attempt}/{MAX_RETRIES} lote {key} en {wait:.1f}s: {e!r}", file=sys.stderr, flush=True)
            time.sleep(wait)


done = uploaded = 0
failed = []
with ThreadPoolExecutor(max_workers=a.workers) as pool:
    futs = {pool.submit(upload_batch, k, v): k for k, v in sorted(batches.items())}
    for fut in as_completed(futs):
        done += 1
        try:
            uploaded += fut.result()
        except Exception as e:  # noqa: BLE001
            failed.append((futs[fut], repr(e)))
            print(f"ERROR lote {futs[fut]}: {e!r}", file=sys.stderr, flush=True)
        if done % a.progress_every == 0:
            print(f"[progreso] {done}/{len(batches)} lotes, {uploaded} ficheros, {len(failed)} lotes fallidos", flush=True)

print(f"Subidos {uploaded} ficheros en {len(batches)} lotes mensuales; {skipped} omitidos (--resume); "
      f"{len(failed)} lotes fallidos")
try:
    connect().cursor().execute(f"ALTER STAGE {STAGE} REFRESH")
except Exception as e:  # noqa: BLE001 - el stage interno puede no tener directory table
    print(f"Aviso: ALTER STAGE REFRESH falló: {e!r}", file=sys.stderr)
if failed:
    print("Lotes fallidos (re-ejecuta con --resume para reintentar sólo lo pendiente):", file=sys.stderr)
    for k, err in sorted(failed):
        print(f"  {k}: {err}", file=sys.stderr)
    sys.exit(1)
