# Runbook: Sospecha de túnel DNS / DGA

**Táctica MITRE:** Command and Control (TA0011), T1071.004 DNS; Exfiltration T1048.

## Indicadores
- Muchos subdominios únicos y largos (más de 30 caracteres, aspecto base32/hex) hacia un mismo dominio.
- Volumen alto de consultas TXT desde un único host.
- Dominio recién registrado o presente en feeds de ciberinteligencia.

## Pasos
1. Identificar el host origen y el usuario asociado (AUTH_ACTIVITY en la misma franja).
2. Comprobar el dominio contra IOC y su antigüedad.
3. Revisar NETWORK_ACTIVITY del host: conexiones a destinos raros o volumen saliente anómalo.
4. Si se confirma: aislar el host desde EDR y bloquear el dominio en el resolver interno.
5. Preservar evidencias: exportar los eventos raw (BRONZE.DNS_RAW) del periodo.

## Caso previo
Marzo 2026: túnel DNS en un servidor de desarrollo, malware de tipo dnscat2. Contención en 2 h aislando el host y bloqueando el dominio.
