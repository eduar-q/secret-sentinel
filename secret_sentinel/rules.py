# Secret Sentinel — reglas de detección.
# Busca credenciales genéricas y patrones de proveedores conocidos.

RULES = [

    # AWS: identificadores y claves secretas.
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])",
        "severity": "HIGH"
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"""(?i)\baws_secret_access_key\s*[:=]\s*(?:"[^"\r\n]{20,}"|'[^'\r\n]{20,}'|(?![A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[))[^\s#]{20,})""",
        "severity": "CRITICAL"
    },

    # GitHub: tokens clásicos y de acceso personal.
    {
        "name": "GitHub Token",
        "pattern": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
        "severity": "HIGH"
    },

    # Stripe: claves secretas y restringidas.
    {
        "name": "Stripe Secret Key",
        "pattern": r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        "severity": "HIGH"
    },
    {
        "name": "Stripe Restricted Key",
        "pattern": r"\brk_(?:live|test)_[A-Za-z0-9]{16,}\b",
        "severity": "HIGH"
    },

    # Slack: tokens de bot, usuario, aplicación y flujos.
    {
        "name": "Slack Token",
        "pattern": r"\b(?:xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[A-Za-z0-9-]{10,}|xwfp-[A-Za-z0-9-]{10,})\b",
        "severity": "HIGH"
    },

    # Claves API genéricas, incluso con prefijos.
    {
        "name": "API Key",
        "pattern": r"""(?i)\b(?:[A-Za-z0-9]+_)*(?:api_key|apikey)\s*[:=]\s*(?:"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|(?! (?-i:[a-z])[A-Za-z0-9_]*\s*(?:$|[;,#]))(?![A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[))[^\s#()]{8,}(?=$|\s|#))""".replace("(?! ", "(?!"),
        "severity": "HIGH"
    },

    # Contraseñas genéricas con nombres como DB_PASSWORD.
    {
        "name": "Password",
        "pattern": r"""(?i)\b(?:[A-Za-z0-9]+_)*(?:password|passwd)\s*[:=]\s*(?:"[^"\r\n]+"|'[^'\r\n]+'|(?! (?-i:[a-z])[A-Za-z0-9_]*\s*(?:$|[;,#]))(?![A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[))[^\s#()]{8,}(?=$|\s|#))""".replace("(?! ", "(?!"),
        "severity": "HIGH"
    },

    # Tokens genéricos de acceso.
    {
        "name": "Access Token",
        "pattern": r"""(?i)\b(?:[A-Za-z0-9]+_)*(?:access_token|auth_token)\s*[:=]\s*(?:"[^"\r\n]{8,}"|'[^'\r\n]{8,}'|(?! (?-i:[a-z])[A-Za-z0-9_]*\s*(?:$|[;,#]))(?![A-Za-z_][A-Za-z0-9_.]*\s*(?:\(|\[))[^\s#()]{8,}(?=$|\s|#))""".replace("(?! ", "(?!"),
        "severity": "HIGH"
    },

    # Encabezados habituales de claves privadas.
    {
        "name": "Private Key",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
        "severity": "CRITICAL"
    }
]
