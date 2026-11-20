import re

from .rules import RULES


def detect_secrets(line: str) -> list[dict[str, str]]:
    """
    Compara una línea de texto con las reglas de Secret Sentinel.

    Devuelve el tipo de coincidencia y su gravedad, sin revelar
    el contenido que podría ser una credencial.
    """
    findings = []

    # Cada regla representa un tipo de credencial que queremos identificar.
    for rule in RULES:

        # Si el patrón aparece en la línea, registramos el hallazgo.
        if re.search(rule["pattern"], line):
            findings.append({
                "name": rule["name"],
                "severity": rule["severity"]
            })

    return findings
