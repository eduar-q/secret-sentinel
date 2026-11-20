import unittest

from secret_sentinel.detector import detect_secrets


class TestSecretDetector(unittest.TestCase):
    """Pruebas para comprobar las detecciones y evitar falsas alertas."""

    def assert_single_finding(self, line, expected_name):
        # Comprueba que se encuentre únicamente el tipo esperado.
        findings = detect_secrets(line)

        self.assertEqual(
            [finding["name"] for finding in findings],
            [expected_name]
        )

    # --------------------------------------------------
    # 1. Credenciales genéricas
    # --------------------------------------------------

    def test_detects_supported_secret_patterns(self):
        # Comprueba las reglas básicas del detector.
        examples = [
            ("api" + '_key = "DEMO_API_KEY_123456789"', "API Key"),
            ("pass" + 'word = "FAKE_PASSWORD_FOR_TESTING"', "Password"),
            ("access" + '_token = "DEMO_ACCESS_TOKEN_987654321"', "Access Token"),
            ('private_key = "-----BEGIN ' + "PRIVATE KEY-----", "Private Key")
        ]

        for line, expected in examples:
            with self.subTest(expected=expected):
                self.assert_single_finding(line, expected)

    def test_detects_unquoted_credentials(self):
        # Comprueba valores escritos sin comillas.
        examples = [
            ("api" + "_key=DEMO_API_KEY_123456789", "API Key"),
            ("pass" + "word=FAKE_PASSWORD_123456", "Password"),
            ("access" + "_token=DEMO_ACCESS_TOKEN_123456789", "Access Token")
        ]

        for line, expected in examples:
            with self.subTest(expected=expected):
                self.assert_single_finding(line, expected)

    def test_detects_prefixed_password_names(self):
        # Comprueba nombres habituales en archivos de configuración.
        examples = [
            ('DB_PASSWORD = "FAKE_DB_PASSWORD_123456"', "Password"),
            ("DATABASE_PASSWORD=FAKE_DATABASE_PASSWORD_123456", "Password"),
            ('MYSQL_PASSWORD = "FAKE_MYSQL_PASSWORD_123456"', "Password")
        ]

        for line, expected in examples:
            with self.subTest(line=line):
                self.assert_single_finding(line, expected)

    # --------------------------------------------------
    # 2. Credenciales de proveedores
    # --------------------------------------------------

    def test_detects_aws_credentials(self):
        # AWS utiliza identificadores y claves secretas diferentes.
        examples = [
            (
                "aws_access_key_id = " + '"AKIA' + "IOSFODNN7EXAMPLE" + '"',
                "AWS Access Key ID"
            ),
            (
                "aws_access_key_id = " + '"ASIA' + "IOSFODNN7EXAMPLE" + '"',
                "AWS Access Key ID"
            ),
            (
                "aws_secret_access_key = " + '"wJalrXtnFEMI' +
                "/K7MDENG/bPxRfiCYEXAMPLEKEY" + '"',
                "AWS Secret Access Key"
            )
        ]

        for line, expected in examples:
            with self.subTest(expected=expected):
                self.assert_single_finding(line, expected)

    def test_detects_github_tokens(self):
        # Comprueba los principales prefijos de tokens de GitHub.
        examples = [
            ('github_token = "ghp' + "_1234567890ABCDEF1234567890AB" + '"'),
            (
                'github_pat = "github_pat' +
                "_11AA22BB33CC44DD55EE_1234567890ABCDEF1234567890" + '"'
            ),
            ('github_oauth = "gho' + "_1234567890ABCDEF1234567890AB" + '"'),
            ('github_user = "ghu' + "_1234567890ABCDEF1234567890AB" + '"'),
            ('github_refresh = "ghr' + "_1234567890ABCDEF1234567890AB" + '"')
        ]

        for line in examples:
            with self.subTest(line=line):
                self.assert_single_finding(line, "GitHub Token")

    def test_detects_stripe_keys(self):
        # Las claves secretas y restringidas deben detectarse.
        examples = [
            ('stripe_key = "sk_live' + "_1234567890ABCDEF123456" + '"',
             "Stripe Secret Key"),
            ('stripe_test = "sk_test' + "_1234567890ABCDEF123456" + '"',
             "Stripe Secret Key"),
            ('stripe_key = "rk_live' + "_1234567890ABCDEF123456" + '"',
             "Stripe Restricted Key"),
            ('stripe_test = "rk_test' + "_1234567890ABCDEF123456" + '"',
             "Stripe Restricted Key")
        ]

        for line, expected in examples:
            with self.subTest(expected=expected):
                self.assert_single_finding(line, expected)

    def test_detects_slack_tokens(self):
        # Comprueba tokens habituales de Slack.
        examples = [
            '"xoxb-1234567890-1234567890-ABCDEF"',
            '"xoxp-1234567890-1234567890-ABCDEF"',
            '"xapp-1234567890-1234567890-ABCDEF"',
            '"xwfp-1234567890-1234567890-ABCDEF"'
        ]

        for token in examples:
            with self.subTest(token=token):
                self.assert_single_finding(token, "Slack Token")

    # --------------------------------------------------
    # 3. Claves privadas
    # --------------------------------------------------

    def test_detects_private_key_headers(self):
        # Comprueba distintos formatos de encabezados PEM.
        key_types = [
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY"
        ]

        for key_type in key_types:
            with self.subTest(key_type=key_type):
                self.assert_single_finding(
                    "-----BEGIN " + key_type + "-----",
                    "Private Key"
                )

    # --------------------------------------------------
    # 4. Casos que NO deben generar alertas
    # --------------------------------------------------

    def test_ignores_environment_variables(self):
        # Obtener una credencial del entorno no significa
        # que esté escrita directamente en el código.
        examples = [
            "pass" + 'word = os.getenv("DB_PASSWORD")',
            "pass" + 'word = os.environ["DB_PASSWORD"]',
            "api" + '_key = os.getenv("API_KEY")',
            "access" + '_token = os.getenv("ACCESS_TOKEN")'
        ]

        for line in examples:
            with self.subTest(line=line):
                self.assertEqual(detect_secrets(line), [])

    def test_ignores_dynamic_references_and_public_values(self):
        # Comprueba parámetros, funciones, URL y valores públicos.
        examples = [
            "access" + "_token = token_recibido",
            "access" + "_token = get_token_from_user()",
            'API_URL = "https://api.ejemplo.com/v1/data?key=12345"',
            'stripe_publishable_key = "pk_test_1234567890ABCDEF"',
            "hash_ejemplo = hashlib.sha256(b'hola').hexdigest()",
            'APP_NAME = "Secret Sentinel"'
        ]

        for line in examples:
            with self.subTest(line=line):
                self.assertEqual(detect_secrets(line), [])

    def test_ignores_comment_lines(self):
        # Una línea que solamente contiene un comentario no debe alertar.
        comment = "# " + 'password = "FAKE_PASSWORD_FOR_DOCUMENTATION"'

        self.assertEqual(detect_secrets(comment), [])

    def test_ignores_regular_text(self):
        # El texto y las configuraciones normales deben ignorarse.
        examples = [
            'APP_NAME = "Secret Sentinel"',
            'DEBUG_MODE = False',
            'mensaje = "Hola, mundo"',
            'MAX_FILE_SIZE = 1048576'
        ]

        for line in examples:
            with self.subTest(line=line):
                self.assertEqual(detect_secrets(line), [])

    # --------------------------------------------------
    # 5. Protección de la información detectada
    # --------------------------------------------------

    def test_does_not_return_secret_value(self):
        # El detector debe informar del hallazgo sin revelar su valor.
        secret = "DEMO_API" + "_KEY_123456789"
        line = "api" + '_key = "' + secret + '"'

        findings = detect_secrets(line)

        self.assertTrue(findings)
        self.assertNotIn(secret, str(findings))


if __name__ == "__main__":
    unittest.main()
