"""Sube la salida local del generador a un stage interno (ensayo sin AWS).

Uso: python upload_internal.py --dir ./out --connection <nombre en connections.toml>
Mantiene el layout <source>/YYYY/MM/DD/ dentro de @SECURITY_LAKE.BRONZE.S3_LOGS.
"""
import argparse
from pathlib import Path

import snowflake.connector

p = argparse.ArgumentParser()
p.add_argument("--dir", required=True)
p.add_argument("--connection", default=None)
a = p.parse_args()

con = snowflake.connector.connect(connection_name=a.connection) if a.connection else snowflake.connector.connect()
cur = con.cursor()
cur.execute("USE ROLE SOC_ADMIN")
cur.execute("USE SCHEMA SECURITY_LAKE.BRONZE")
root = Path(a.dir).resolve()
dirs = sorted({f.parent for f in root.rglob("*") if f.is_file()})
for d in dirs:
    rel = d.relative_to(root).as_posix()
    cur.execute(f"PUT 'file://{d}/*' @S3_LOGS/{rel}/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE PARALLEL=8")
print(f"Subidos {len(dirs)} directorios")
cur.execute("ALTER STAGE S3_LOGS REFRESH")
