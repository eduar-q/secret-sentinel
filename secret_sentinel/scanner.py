import os
from pathlib import Path

from .detector import detect_secrets


# Estas carpetas suelen contener dependencias o archivos generados.
# No necesitamos revisarlas para buscar credenciales del proyecto.
EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "build",
    "dist"
}


def scan_directory(root: str | Path) -> list[dict]:
    """
    Recorre un directorio y busca posibles credenciales en sus archivos.

    Cada hallazgo incluye la ruta, la línea, el tipo de coincidencia
    y su gravedad. El contenido sensible no se guarda en el resultado.
    """
    root_path = Path(root).resolve()

    # Evitamos iniciar un escaneo sobre una ruta inexistente o inválida.
    if not root_path.is_dir():
        raise ValueError(f"El directorio no existe: {root_path}")

    findings = []

    # os.walk permite recorrer las carpetas sin entrar en las excluidas.
    for current_dir, directory_names, file_names in os.walk(root_path):

        # Filtramos las carpetas antes de continuar el recorrido.
        directory_names[:] = [
            name for name in directory_names
            if name not in EXCLUDED_DIRS
        ]

        for file_name in file_names:
            file_path = Path(current_dir) / file_name

            try:
                # Comprobamos si parece un archivo binario antes de leerlo
                # como texto, para evitar analizar imágenes y ejecutables.
                with file_path.open("rb") as file:
                    sample = file.read(1024)

                if b"\x00" in sample:
                    continue

                # Revisamos el archivo línea por línea para conocer
                # exactamente dónde aparece cada posible credencial.
                with file_path.open(
                    "r",
                    encoding="utf-8",
                    errors="replace"
                ) as file:

                    for line_number, line in enumerate(file, start=1):
                        matches = detect_secrets(line)

                        for match in matches:
                            findings.append({
                                "file": str(file_path.relative_to(root_path)),
                                "line": line_number,
                                "name": match["name"],
                                "severity": match["severity"]
                            })

            except OSError:
                # Un archivo inaccesible no debe detener todo el escaneo.
                continue

    return findings
