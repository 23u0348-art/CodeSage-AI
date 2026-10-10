import unittest
from bandit_analyzer import run_bandit


class TestBanditIntegration(unittest.TestCase):

    def test_detects_eval(self):
        code = "result = eval(user_input)\n"
        result = run_bandit(code)

        self.assertIsNone(result["error"])

        test_ids = [
            item.get("test_id", "")
            for item in result["findings"]
        ]

        self.assertIn(
            "B307",
            test_ids,
            f"Expected Bandit rule B307 for eval(). Got: {result['findings']}"
        )


if __name__ == "__main__":
    unittest.main()