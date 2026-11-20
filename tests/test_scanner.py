import tempfile
import unittest
from pathlib import Path

from secret_sentinel.scanner import scan_directory


class TestDirectoryScanner(unittest.TestCase):
    """Pruebas para comprobar el recorrido seguro de archivos y carpetas."""

    def setUp(self):
        # Cada prueba utiliza su propia carpeta temporal.
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.base = Path(self.temp_dir.name)
        self.root = self.base / "project"
        self.root.mkdir()

    def test_finds_secrets_in_files(self):
        # Comprueba la detección de credenciales genéricas.
        sample = self.root / "config.py"

        content = "\n".join([
            'APP_NAME = "Demo"',
            "api" + '_key = "DEMO_API_KEY_123456789"',
            "pass" + 'word = "FAKE_PASSWORD_FOR_TESTING"',
            "access" + '_token = "DEMO_ACCESS_TOKEN_987654321"',
            'private_key = "-----BEGIN ' + "PRIVATE KEY-----"
        ])

        sample.write_text(content, encoding="utf-8")

        findings = scan_directory(self.root)

        self.assertEqual(len(findings), 4)

        self.assertEqual(
            {item["name"] for item in findings},
            {"API Key", "Password", "Access Token", "Private Key"}
        )

        self.assertTrue(
            all(item["file"] == "config.py" for item in findings)
        )

        self.assertEqual(
            [item["line"] for item in findings],
            [2, 3, 4, 5]
        )

    def test_finds_provider_credentials_in_files(self):
        # Comprueba que el escáner reconoce los siete casos de la prueba sucia.
        sample = self.root / "providers.env"

        content = "\n".join([
            "aws_access_key_id = " + '"AKIA' + "IOSFODNN7EXAMPLE" + '"',
            "aws_secret_access_key = " + '"wJalrXtnFEMI' +
            "/K7MDENG/bPxRfiCYEXAMPLEKEY" + '"',
            "github_token = " + '"ghp' +
            "_16C7e42F292c6912E7710c838347Ae178B4a" + '"',
            "stripe_key = " + '"sk_live' +
            "_51MzQ2L2eZvKYlo2CwHJvO8xJ" + '"',
            "DB_" + "PASSWORD=SuperSecreto123!",
            "-----BEGIN RSA " + "PRIVATE KEY-----",
            "slack_token = " + '"xoxb-' +
            "123456789012-1234567890123-AbCdEfGhIjKlMnOpStUvWx" + '"'
        ])

        sample.write_text(content, encoding="utf-8")

        findings = scan_directory(self.root)

        expected_names = [
            "AWS Access Key ID",
            "AWS Secret Access Key",
            "GitHub Token",
            "Stripe Secret Key",
            "Password",
            "Private Key",
            "Slack Token"
        ]

        self.assertEqual(
            [item["name"] for item in findings],
            expected_names
        )

        self.assertEqual(len(findings), 7)

        # El resultado no debe revelar los valores detectados.
        self.assertNotIn("SuperSecreto123!", str(findings))

    def test_ignores_clean_configuration(self):
        # Comprueba que un archivo limpio no produzca falsas alertas.
        sample = self.root / "settings.py"

        content = "\n".join([
            "DB_PASSWORD = os.getenv('DB_PASSWORD')",
            'API_TOKEN = os.environ["API_TOKEN"]',
            'API_URL = "https://api.ejemplo.com/v1/data?key=12345"',
            'stripe_publishable_key = "pk_test_1234567890ABCDEF"',
            "access_token = token_recibido",
            'APP_NAME = "Secret Sentinel"'
        ])

        sample.write_text(content, encoding="utf-8")

        self.assertEqual(scan_directory(self.root), [])

    def test_ignores_excluded_directories(self):
        # El contenido del entorno virtual debe quedar excluido.
        excluded_file = self.root / ".venv" / "lib" / "module.py"
        excluded_file.parent.mkdir(parents=True)

        excluded_file.write_text(
            "api" + '_key = "DEMO_API_KEY_123456789"',
            encoding="utf-8"
        )

        self.assertEqual(scan_directory(self.root), [])

    def test_ignores_regular_files(self):
        # Los archivos sin credenciales no deben generar alertas.
        safe_file = self.root / "settings.py"

        safe_file.write_text(
            'APP_NAME = "Secret Sentinel"',
            encoding="utf-8"
        )

        self.assertEqual(scan_directory(self.root), [])

    def test_scans_nested_directories(self):
        # Comprueba que también se revisen las subcarpetas normales.
        nested_file = self.root / "src" / "config.py"
        nested_file.parent.mkdir(parents=True)

        nested_file.write_text(
            "api" + '_key = "DEMO_API_KEY_123456789"',
            encoding="utf-8"
        )

        findings = scan_directory(self.root)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["file"], "src/config.py")
        self.assertEqual(findings[0]["line"], 1)

    def test_ignores_binary_files(self):
        # Los archivos binarios no deben analizarse como texto.
        binary_file = self.root / "data.bin"

        binary_file.write_bytes(
            b"\x00\x01\x02password = FAKE_PASSWORD_123456"
        )

        self.assertEqual(scan_directory(self.root), [])

    def test_ignores_symlink_files_outside_root(self):
        # Un enlace a un archivo externo no debe permitir salir del proyecto.
        outside_file = self.base / "outside.py"

        outside_file.write_text(
            "pass" + 'word = "FAKE_PASSWORD_FOR_TESTING"',
            encoding="utf-8"
        )

        link = self.root / "external.py"

        try:
            link.symlink_to(outside_file)
        except (OSError, NotImplementedError):
            self.skipTest("El sistema no permite crear enlaces simbólicos.")

        self.assertEqual(scan_directory(self.root), [])

    def test_ignores_symlink_directories(self):
        # No se deben recorrer directorios externos mediante enlaces.
        outside_dir = self.base / "external"
        outside_dir.mkdir()

        external_file = outside_dir / "secret.py"

        external_file.write_text(
            "pass" + 'word = "FAKE_PASSWORD_FOR_TESTING"',
            encoding="utf-8"
        )

        link = self.root / "external_link"

        try:
            link.symlink_to(outside_dir, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("El sistema no permite crear enlaces simbólicos.")

        self.assertEqual(scan_directory(self.root), [])

    def test_rejects_nonexistent_directory(self):
        # Una ruta inexistente debe generar un error controlado.
        missing = self.root / "missing"

        with self.assertRaises(ValueError):
            scan_directory(missing)


if __name__ == "__main__":
    unittest.main()
