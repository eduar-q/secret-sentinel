import argparse
import sys

from .scanner import scan_directory


def main():
    # Permite indicar qué carpeta queremos inspeccionar.
    # Si no se especifica ninguna, se revisa el directorio actual.
    parser = argparse.ArgumentParser(
        description="Busca posibles credenciales expuestas en archivos."
    )

    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Carpeta que se desea analizar."
    )

    args = parser.parse_args()

    try:
        findings = scan_directory(args.directory)
    except ValueError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    # Un resultado vacío significa que no hubo coincidencias.
    if not findings:
        print("No se encontraron posibles credenciales.")
        return 0

    # Mostramos únicamente los datos necesarios para revisar cada alerta.
    print("\nPOSIBLES CREDENCIALES DETECTADAS\n")

    print(f"{'ARCHIVO':<35} {'LINEA':<8} {'TIPO':<16} {'GRAVEDAD'}")
    print("-" * 75)

    for finding in findings:
        print(
            f"{finding['file']:<35} "
            f"{finding['line']:<8} "
            f"{finding['name']:<16} "
            f"{finding['severity']}"
        )

    print(f"\nTotal de coincidencias: {len(findings)}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
