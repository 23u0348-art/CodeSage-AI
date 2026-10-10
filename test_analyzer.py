
import unittest
from analyzer import analyze_code


class TestCodeSageAI(unittest.TestCase):

    def test_detects_eval(self):
        code = "result = eval(user_input)"
        result = analyze_code(code)

        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Use of eval()", titles)

    def test_detects_hardcoded_secret(self):
        code = 'API_KEY = "my-secret-key-123"'
        result = analyze_code(code)

        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Possible hard-coded secret", titles)

    def test_detects_mutable_default(self):
        code = (
            "def example(items=[]):\n"
            "    return items\n"
        )
        result = analyze_code(code)

        titles = [item["title"] for item in result["findings"]]
        self.assertIn("Mutable default argument", titles)

    def test_clean_code_has_no_findings(self):
        code = (
            "def add(a, b):\n"
            "    return a + b\n"
        )
        result = analyze_code(code)

        self.assertEqual(len(result["findings"]), 0)

    def test_detects_syntax_error(self):
        code = "def broken(:\n    pass"
        result = analyze_code(code)

        self.assertIsNotNone(result["syntax_error"])


if __name__ == "__main__":
    unittest.main()
