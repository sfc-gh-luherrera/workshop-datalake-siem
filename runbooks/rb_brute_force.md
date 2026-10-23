# Runbook: Fuerza bruta con acceso exitoso

**Táctica MITRE:** Credential Access (TA0006), T1110 Brute Force; Privilege Escalation T1078.

## Indicadores
- Ráfaga de eventos 4625 (fallo de inicio de sesión) para una cuenta desde una misma IP.
- Seguido de 4624 (éxito) y 4672 (privilegios especiales).
- Cuentas de servicio o IP externas (nodos Tor, proveedores de hosting) agravan la severidad.

## Pasos
1. Deshabilitar o rotar la credencial de la cuenta afectada.
2. Revisar qué hizo la cuenta tras el acceso: AUTH_ACTIVITY y NETWORK_ACTIVITY en las 24 h siguientes.
3. Comprobar la IP origen contra IOC y bloquearla en el perímetro.
4. Si es cuenta de servicio: verificar que no tiene inicio de sesión interactivo permitido.
5. Escalar a CSIRT si hubo uso de privilegios.
