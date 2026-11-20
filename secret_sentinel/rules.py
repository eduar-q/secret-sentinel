# Secret Sentinel — reglas iniciales de detección.
# Cada regla busca una señal habitual de credenciales guardadas
# directamente en archivos del proyecto.

RULES = [
    {
        # Identifica asignaciones de claves API mediante nombres habituales.
        "name": "API Key",
        "pattern": r"""(?i)(api_key|apikey)\s*[:=]\s*['"][^'"]{8,}['"]""",
        "severity": "HIGH"
    },
    {
        # Busca contraseñas escritas como valores dentro del código.
        "name": "Password",
        "pattern": r"""(?i)(password|passwd)\s*[:=]\s*['"][^'"]+['"]""",
        "severity": "HIGH"
    },
    {
        # Reconoce nombres frecuentes de tokens de autenticación.
        "name": "Access Token",
        "pattern": r"""(?i)(access_token|auth_token)\s*[:=]\s*['"][^'"]{8,}['"]""",
        "severity": "HIGH"
    },
    {
        # Detecta el encabezado de una clave privada, aunque su contenido
        # esté distribuido en varias líneas.
        "name": "Private Key",
        "pattern": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL"
    }
]
