import os
from pathlib import Path

from .detector import detect_secrets


# Carpetas que contienen dependencias, archivos de Git
# o contenido generado que no necesitamos analizar.
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
    Recorre un directorio y busca posibles credenciales.

    No sigue enlaces simbólicos, no analiza archivos binarios
    y continúa el escaneo cuando encuentra archivos inaccesibles.
    """

    input_path = Path(root).expanduser()

    # No permitimos que la carpeta raíz sea un enlace simbólico.
    if input_path.is_symlink():
        raise ValueError("El directorio indicado no puede ser un enlace simbólico.")

    try:
        root_path = input_path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(
            f"El directorio no existe o no se puede resolver: {input_path}"
        )

    if not root_path.is_dir():
        raise ValueError(f"El directorio no existe: {root_path}")

    findings = []

    # Recorremos los directorios sin seguir enlaces simbólicos.
    for current_dir, directory_names, file_names in os.walk(
        root_path,
        topdown=True,
        followlinks=False
    ):
        current_path = Path(current_dir)

        # Excluimos las carpetas configuradas y los enlaces simbólicos.
        directory_names[:] = [
            name for name in directory_names
            if name not in EXCLUDED_DIRS
            and not (current_path / name).is_symlink()
        ]

        for file_name in file_names:
            file_path = current_path / file_name

            try:
                # Ignoramos enlaces simbólicos y elementos que no sean
                # archivos regulares.
                if file_path.is_symlink() or not file_path.is_file():
                    continue

                # Comprobamos una muestra del archivo para identificar
                # contenido binario antes de tratarlo como texto.
                with file_path.open("rb") as file:
                    sample = file.read(8192)

                if b"\x00" in sample:
                    continue

                # Leemos línea por línea para mantener un consumo
                # de memoria reducido incluso con archivos grandes.
                with file_path.open(
                    "r",
                    encoding="utf-8",
                    errors="replace"
                ) as file:

                    for line_number, line in enumerate(file, start=1):
                        matches = detect_secrets(line)

                        for match in matches:
                            findings.append({
                                "file": str(
                                    file_path.relative_to(root_path)
                                ),
                                "line": line_number,
                                "name": match["name"],
                                "severity": match["severity"]
                            })

            except OSError:
                # Un archivo inaccesible no debe detener todo el análisis.
                continue

    return findings
