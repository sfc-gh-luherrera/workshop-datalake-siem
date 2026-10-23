# Runbook: Descarga masiva en Office 365 / SharePoint

**Táctica MITRE:** Collection (TA0009), T1530 Data from Cloud Storage.

## Indicadores
- Más de 100 FileDownloaded por usuario y hora.
- IP de origen nueva para el usuario, fuera de horario o desde otro país.

## Pasos
1. Revocar sesiones y tokens del usuario en Entra ID; forzar cambio de contraseña y MFA.
2. Comprobar si la IP origen coincide con IOC o con un inicio de sesión sospechoso previo.
3. Listar los ficheros descargados y su clasificación de sensibilidad.
4. Contactar con el usuario y su responsable para validar la actividad.
5. Si no es legítima: tratar como incidente de fuga de información.
