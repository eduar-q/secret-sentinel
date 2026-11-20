import re

from .rules import RULES


def detect_secrets(line: str) -> list[dict[str, str]]:
    """
    Compara una línea de texto con las reglas de Secret Sentinel.

    Ignora líneas vacías y comentarios completos.
    Devuelve el tipo de coincidencia y su gravedad,
    sin revelar el contenido que podría ser una credencial.
    """

    # No analizamos líneas vacías ni comentarios de Python,
    # archivos .env y otros formatos que utilizan #.
    stripped_line = line.lstrip()

    if not stripped_line or stripped_line.startswith("#"):
        return []

    findings = []

    # Comparamos la línea con todas las reglas disponibles.
    for rule in RULES:
        if re.search(rule["pattern"], line):
            findings.append({
                "name": rule["name"],
                "severity": rule["severity"]
            })

    return findings
