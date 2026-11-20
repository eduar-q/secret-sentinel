import unittest

from secret_sentinel.detector import detect_secrets


class TestSecretDetector(unittest.TestCase):
    """Comprueba que el detector reconoce las señales previstas."""

    def test_detects_supported_secret_patterns(self):
        # Construimos los ejemplos por partes para que el escáner
        # no confunda el código de prueba con credenciales expuestas.
        examples = [
            ("api" + '_key = "DEMO_API_KEY_123456789"', "API Key"),
            ("pass" + 'word = "FAKE_PASSWORD_FOR_TESTING"', "Password"),
            ("access" + '_token = "DEMO_ACCESS_TOKEN_987654321"', "Access Token"),
            ('private_key = "-----BEGIN ' + 'PRIVATE KEY-----"', "Private Key")
        ]

        for line, expected_name in examples:
            with self.subTest(secret_type=expected_name):
                findings = detect_secrets(line)

                self.assertTrue(findings)
                self.assertEqual(findings[0]["name"], expected_name)

    def test_ignores_regular_text(self):
        # Una línea sin credenciales no debería generar ningún hallazgo.
        findings = detect_secrets('APP_NAME = "Secret Sentinel"')

        self.assertEqual(findings, [])

    def test_does_not_return_secret_value(self):
        # Dividimos el ejemplo para evitar una coincidencia en este archivo.
        secret = "DEMO_API" + "_KEY_123456789"
        line = "api" + '_key = "' + secret + '"'

        findings = detect_secrets(line)

        self.assertNotIn(secret, str(findings))

    def test_detects_unquoted_credentials(self):
        # Comprueba que también se reconocen valores sin comillas.
        examples = [
            ("api" + "_key=DEMO_API_KEY_123456789", "API Key"),
            ("pass" + "word=FAKE_PASSWORD_123456", "Password"),
            ("access" + "_token=DEMO_ACCESS_TOKEN_987654321", "Access Token")
        ]

        for line, expected_name in examples:
            with self.subTest(secret_type=expected_name):
                findings = detect_secrets(line)

                self.assertTrue(findings)
                self.assertEqual(findings[0]["name"], expected_name)

    def test_ignores_environment_variable_lookup(self):
        # Obtener una contraseña mediante getenv no es una asignación literal.
        line = "pass" + 'word = os.getenv("DB_PASSWORD")'

        findings = detect_secrets(line)

        self.assertEqual(findings, [])

    def test_ignores_environment_mapping(self):
        # Comprueba el acceso mediante os.environ["..."].
        line = "pass" + 'word = os.environ["DB_' + "PASSWORD" + '"]'

        findings = detect_secrets(line)

        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
