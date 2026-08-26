# MailSleuth

Analizador local de mensajes `.eml` para triage de phishing. Revisa cabeceras, saltos de entrega y enlaces sin ejecutar adjuntos ni conectarse a Internet.

`python3 mailsleuth.py mensaje.eml --output informe.json`

## Ejemplo

El informe incluye remitente, asunto, cantidad de saltos, enlaces observados y hallazgos. Los adjuntos nunca se ejecutan ni se abren.

```json
{"findings": [{"rule": "suspicious-link", "severity": "medium"}]}
```
