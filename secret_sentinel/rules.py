# Secret Sentinel — reglas de detección de credenciales.
# Busca patrones habituales de secretos en código y archivos
# de configuración, evitando algunas referencias dinámicas.

RULES = [
    {
        # Detecta claves API con o sin comillas.
        "name": "API Key",
        "pattern": r"""(?i)(api_key|apikey)\s*[:=]\s*(?:'[^'\r\n]{8,}'|"[^"\r\n]{8,}"|(?![A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[))[^\s#()]{8,}(?=$|\s|#))""",
        "severity": "HIGH"
    },
    {
        # Detecta contraseñas asignadas directamente.
        # Evita confundir referencias a funciones o variables indexadas
        # con valores de contraseñas escritos directamente.
        "name": "Password",
        "pattern": r"""(?i)(password|passwd)\s*[:=]\s*(?:'[^'\r\n]+'|"[^"\r\n]+"|(?![A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[))[^\s#()]+(?=$|\s|#))""",
        "severity": "HIGH"
    },
    {
        # Detecta tokens de acceso con o sin comillas.
        "name": "Access Token",
        "pattern": r"""(?i)(access_token|auth_token)\s*[:=]\s*(?:'[^'\r\n]{8,}'|"[^"\r\n]{8,}"|(?![A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[))[^\s#()]{8,}(?=$|\s|#))""",
        "severity": "HIGH"
    },
    {
        # Detecta encabezados habituales de claves privadas.
        # No valida el contenido criptográfico de la clave.
        "name": "Private Key",
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL"
    }
]
