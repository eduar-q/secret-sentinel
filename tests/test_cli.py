import contextlib
import io
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from secret_sentinel.__main__ import main


class TestCommandLine(unittest.TestCase):
    """Comprueba los resultados de Secret Sentinel desde la terminal."""

    def setUp(self):
        # Cada prueba utiliza una carpeta temporal independiente.
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def run_cli(self, directory):
        # Ejecuta el programa y captura lo que muestra en pantalla.
        output = io.StringIO()
        errors = io.StringIO()

        with patch("sys.argv", ["secret-sentinel", str(directory)]):
            with contextlib.redirect_stdout(output):
                with contextlib.redirect_stderr(errors):
                    exit_code = main()

        return exit_code, output.getvalue(), errors.getvalue()

    def test_returns_zero_when_no_secrets_are_found(self):
        # Una carpeta limpia debe finalizar sin alertas.
        sample = self.root / "clean.py"
        sample.write_text(
            'APP_NAME = "Secret Sentinel"',
            encoding="utf-8"
        )

        exit_code, output, errors = self.run_cli(self.root)

        self.assertEqual(exit_code, 0)
        self.assertIn("No se encontraron", output)
        self.assertEqual(errors, "")

    def test_returns_one_when_secrets_are_found(self):
        # Una credencial detectada debe generar el código de salida 1.
        secret = "FAKE_PASSWORD_DO_NOT_EXPOSE_123"
        sample = self.root / "config.py"

        sample.write_text(
            'password = "' + secret + '"',
            encoding="utf-8"
        )

        exit_code, output, errors = self.run_cli(self.root)

        self.assertEqual(exit_code, 1)
        self.assertIn("Password", output)
        self.assertNotIn(secret, output)
        self.assertEqual(errors, "")

    def test_returns_two_for_missing_directory(self):
        # Una ruta inexistente debe generar un error controlado.
        missing = self.root / "missing"

        exit_code, output, errors = self.run_cli(missing)

        self.assertEqual(exit_code, 2)
        self.assertEqual(output, "")
        self.assertIn("Error:", errors)


if __name__ == "__main__":
    unittest.main()
