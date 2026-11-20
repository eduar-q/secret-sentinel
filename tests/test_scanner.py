import tempfile
import unittest
from pathlib import Path

from secret_sentinel.scanner import scan_directory


class TestDirectoryScanner(unittest.TestCase):
    """Comprueba cómo se comporta el escáner al recorrer carpetas."""

    def setUp(self):
        # Cada prueba recibe su propio directorio temporal.
        # Así no modificamos los archivos reales de Secret Sentinel.
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def test_finds_secrets_in_files(self):
        # Simulamos un archivo de configuración con cuatro señales.
        sample = self.root / "config.py"

        content = "\n".join([
            'APP_NAME = "Demo"',
            "api" + '_key = "DEMO_API_KEY_123456789"',
            "pass" + 'word = "FAKE_PASSWORD_FOR_TESTING"',
            "access" + '_token = "DEMO_ACCESS_TOKEN_987654321"',
            'private_key = "-----BEGIN ' + 'PRIVATE KEY-----"'
        ])

        sample.write_text(content, encoding="utf-8")

        findings = scan_directory(self.root)

        # El escáner debe reconocer los cuatro tipos y señalar su ubicación.
        self.assertEqual(len(findings), 4)
        self.assertEqual(
            {item["name"] for item in findings},
            {"API Key", "Password", "Access Token", "Private Key"}
        )
        self.assertTrue(all(item["file"] == "config.py" for item in findings))
        self.assertEqual([item["line"] for item in findings], [2, 3, 4, 5])

    def test_ignores_excluded_directories(self):
        # Simulamos una credencial dentro del entorno virtual.
        # Esa carpeta no debe formar parte del análisis.
        excluded_file = self.root / ".venv" / "lib" / "module.py"
        excluded_file.parent.mkdir(parents=True)
        excluded_file.write_text(
            "api" + '_key = "DEMO_API_KEY_123456789"',
            encoding="utf-8"
        )

        findings = scan_directory(self.root)

        self.assertEqual(findings, [])

    def test_ignores_regular_files(self):
        # Un archivo sin señales de credenciales no debe generar alertas.
        safe_file = self.root / "settings.py"
        safe_file.write_text(
            'APP_NAME = "Secret Sentinel"',
            encoding="utf-8"
        )

        findings = scan_directory(self.root)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
