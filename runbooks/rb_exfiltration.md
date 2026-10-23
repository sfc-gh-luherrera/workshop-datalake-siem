# Runbook: Exfiltración de datos

**Táctica MITRE:** Exfiltration (TA0010), T1041 / T1567.

## Indicadores
- Bytes salientes diarios de un host muy por encima de su línea base (más de 20 veces).
- Destino externo poco habitual, a menudo en puerto 443.
- Alerta IDS de transferencia TLS grande a destino raro.

## Pasos
1. Confirmar el volumen y el destino en NETWORK_ACTIVITY; comprobar el destino contra IOC.
2. Identificar el proceso y usuario en el host (EDR).
3. Bloquear el destino en el firewall y aislar el host.
4. Determinar qué datos salieron (DLP, accesos a ficheros previos).
5. Evaluar notificación a la autoridad de protección de datos (72 h, RGPD) con el DPO.
